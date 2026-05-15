from fastapi import FastAPI, UploadFile, Form, File, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from PIL import Image
from cryptography.fernet import Fernet
import base64
import urllib.parse
import io
import numpy as np

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "*", 
        "https://cj7-code-journey.github.io"
    ], 
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"]
)

CONTENT_TEXT = 0
CONTENT_FILE = 2 
# AES Fernet output is Base64, it only contains letters, numbers, and =, -, _
# So '::::END::::' is a 100% safe and fast byte delimiter.
DELIMITER = b'::::END::::' 

def generate_key(passcode: str) -> Fernet:
    key = base64.urlsafe_b64encode(passcode.ljust(32).encode()[:32])
    return Fernet(key)

@app.post("/encode")
async def encode(
    carrier: UploadFile = File(...), 
    payload: UploadFile = File(None), 
    text_data: str = Form(None),
    passcode: str = Form(...)
):
    try:
        # Load image and convert to numpy array instantly
        img = Image.open(io.BytesIO(await carrier.read())).convert('RGBA').convert('RGB')
        img_arr = np.array(img)
        
        # Prepare payload
        if text_data:
            content_bytes = text_data.encode('utf-8')
            raw_payload = bytes([CONTENT_TEXT]) + content_bytes
        elif payload:
            file_bytes = await payload.read()
            fname_bytes = payload.filename.encode('utf-8')
            raw_payload = bytes([CONTENT_FILE]) + bytes([len(fname_bytes)]) + fname_bytes + file_bytes
        else:
            raise ValueError("No payload provided.")

        # Encrypt and add delimiter
        cipher = generate_key(passcode)
        encrypted_payload = cipher.encrypt(raw_payload) + DELIMITER

        # VECTORIZED BIT EXTRACTION (Lightning Fast)
        # Convert bytes directly to an array of bits [1, 0, 1, 1...]
        bit_arr = np.unpackbits(np.frombuffer(encrypted_payload, dtype=np.uint8))
        total_bits = len(bit_arr)

        # Flatten image array to 1D
        flat_img = img_arr.flatten()

        if total_bits > len(flat_img):
            raise ValueError("Carrier image capacity exceeded. Use a larger image or smaller file.")

        # VECTORIZED LSB MODIFICATION (The Magic Trick)
        # 1. Clear the LSB of the pixels we need to modify (bitwise AND with ~1 / 254)
        # 2. Inject the payload bits (bitwise OR with bit_arr)
        #  optimized line (Fix)
        flat_img[:total_bits] = (flat_img[:total_bits] & 254) | bit_arr

        # Reshape back to image dimensions and save
        encoded_img = Image.fromarray(flat_img.reshape(img_arr.shape))
        img_byte_arr = io.BytesIO()
        encoded_img.save(img_byte_arr, format='PNG')
        
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
        # Load image as numpy array
        img = Image.open(io.BytesIO(await stego_image.read())).convert('RGBA').convert('RGB')
        flat_img = np.array(img).flatten()
        
        # VECTORIZED LSB EXTRACTION (Lightning Fast)
        # 1. Extract the LSB from EVERY pixel instantly
        extracted_bits = flat_img & 1
        
        # 2. Pack the bits back into bytes instantly
        extracted_bytes = np.packbits(extracted_bits).tobytes()
        
        # Find the delimiter to know where the data ends
        end_idx = extracted_bytes.find(DELIMITER)
        
        if end_idx == -1:
            raise ValueError("No hidden data found or corrupted image.")

        # Isolate the encrypted portion and decrypt
        encrypted_data = extracted_bytes[:end_idx]
        cipher = generate_key(passcode)
        decrypted = cipher.decrypt(encrypted_data)

        ctype = decrypted[0]
        data = decrypted[1:]

        if ctype == CONTENT_TEXT:
            return {"type": "text", "data": data.decode('utf-8')}
        
        elif ctype == CONTENT_FILE:
            fname_len = data[0]
            filename = data[1:1+fname_len].decode('utf-8')
            file_data = data[1+fname_len:]
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
