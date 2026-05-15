from fastapi import FastAPI, UploadFile, Form, File, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from PIL import Image
from cryptography.fernet import Fernet
import base64
import hashlib
import io
import random
import urllib.parse

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Allow frontend to access
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Constants from your code
CONTENT_TEXT = 0
CONTENT_FILE = 2 # We treat Image, File, Audio, Video all as binary files for web simplicity
DELIMITER = '1111111111111110'

def generate_key(passcode: str) -> Fernet:
    key = base64.urlsafe_b64encode(passcode.ljust(32).encode()[:32])
    return Fernet(key)

def content_to_binary(content: bytes) -> str:
    return ''.join(format(byte, '08b') for byte in content)

def binary_to_content(binary_str: str) -> bytes:
    return bytes(int(binary_str[i:i+8], 2) for i in range(0, len(binary_str), 8))

def get_pixel_order(width, height, channels, passcode):
    seed = int(hashlib.sha256(passcode.encode()).hexdigest()[:8], 16)
    coords = [(x, y, c) for x in range(width) for y in range(height) for c in range(channels)]
    random.Random(seed).shuffle(coords)
    return coords

@app.post("/encode")
async def encode(
    carrier: UploadFile = File(...), 
    payload: UploadFile = File(None), 
    text_data: str = Form(None),
    passcode: str = Form(...)
):
    try:
        # 1. Read Carrier Image
        img = Image.open(io.BytesIO(await carrier.read())).convert('RGB')
        pixels = img.load()
        width, height = img.size
        
        # 2. Prepare Payload Bytes
        if text_data:
            content_bytes = text_data.encode('utf-8')
            raw_payload = bytes([CONTENT_TEXT]) + content_bytes
        elif payload:
            file_bytes = await payload.read()
            fname_bytes = payload.filename.encode('utf-8')
            # Format: [TYPE] [FILENAME_LEN] [FILENAME] [FILE_DATA]
            raw_payload = bytes([CONTENT_FILE]) + bytes([len(fname_bytes)]) + fname_bytes + file_bytes
        else:
            raise ValueError("No payload provided.")

        # 3. Encrypt
        cipher = generate_key(passcode)
        encrypted = cipher.encrypt(raw_payload)
        binary_data = content_to_binary(encrypted) + DELIMITER

        if len(binary_data) > (width * height * 3):
            raise ValueError("Carrier image capacity exceeded. Use a larger image or smaller payload.")

        # 4. Hide Data (Randomized LSB)
        pixel_order = get_pixel_order(width, height, 3, passcode)
        idx = 0
        
        for x, y, c in pixel_order:
            if idx >= len(binary_data): break
            pixel = list(pixels[x, y])
            # Modify the LSB of the specific color channel
            pixel[c] = (pixel[c] & ~1) | int(binary_data[idx])
            pixels[x, y] = tuple(pixel)
            idx += 1

        # 5. Return Image
        img_byte_arr = io.BytesIO()
        img.save(img_byte_arr, format='PNG')
        
        return Response(
            content=img_byte_arr.getvalue(), 
            media_type="image/png", 
            headers={"Content-Disposition": "attachment; filename=stego.png"}
        )

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/decode")
async def decode(
    stego_image: UploadFile = File(...), 
    passcode: str = Form(...)
):
    try:
        img = Image.open(io.BytesIO(await stego_image.read())).convert('RGB')
        pixels = img.load()
        width, height = img.size
        
        binary_data = ''
        pixel_order = get_pixel_order(width, height, 3, passcode)
        
        # Extract bits
        for x, y, c in pixel_order:
            pixel = pixels[x, y]
            binary_data += str(pixel[c] & 1)
            if binary_data.endswith(DELIMITER):
                binary_data = binary_data[:-len(DELIMITER)]
                break
                
        if not binary_data:
            raise ValueError("No hidden data found or wrong password.")

        # Decrypt
        encrypted = binary_to_content(binary_data)
        cipher = generate_key(passcode)
        decrypted = cipher.decrypt(encrypted)

        ctype = decrypted[0]
        data = decrypted[1:]

        # Handle Return Data
        if ctype == CONTENT_TEXT:
            return {"type": "text", "data": data.decode('utf-8')}
        
        elif ctype == CONTENT_FILE:
            fname_len = data[0]
            filename = data[1:1+fname_len].decode('utf-8')
            file_data = data[1+fname_len:]
            
            # Encode filename to handle spaces/special characters in headers properly
            safe_filename = urllib.parse.quote(filename)
            
            return Response(
                content=file_data, 
                media_type="application/octet-stream", 
                headers={
                    "Content-Disposition": f"attachment; filename*=UTF-8''{safe_filename}",
                    "Access-Control-Expose-Headers": "Content-Disposition"
                }
            )

    except Exception as e:
        raise HTTPException(status_code=400, detail="Extraction failed. Wrong passcode or corrupted image.")