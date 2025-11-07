import requests
import json
import base64
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

# 配置
PUBLIC_KEY_URL = "https://chat.yhchat.com/assets/key/apps_public.pem" # 公钥的直接下载地址
API_ENDPOINT = "https://chat-go.jwzhd.com/v1/mount-setting/list"
GROUP_ID = "979377289" # 示例groupId

# 换成实际的用户token
# 例如: uuid4
YOUR_AUTH_TOKEN = "" 

# 获取公钥文件
def get_public_key(url):
    try:
        response = requests.get(url)
        response.raise_for_status() # 检查http错误
        return response.content
    except requests.exceptions.RequestException as e:
        print(f"Error fetching public key from {url}: {e}")
        return None

# 生成随机的对称密钥和初始化向量 (IV)
def generate_random_bytes(length):
    return os.urandom(length)

# 使用公钥进行 RSA 加密
def rsa_encrypt(public_key_bytes, data_to_encrypt):
    try:
        # 加载PEM格式的公钥
        public_key = serialization.load_pem_public_key(
            public_key_bytes,
            backend=default_backend()
        )
        
        # 使用PKCS1_OAEP填充进行加密
        encrypted_data = public_key.encrypt(
            data_to_encrypt,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()), # 基于源代码main.dart.js里面使用SHA256
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_data
    except Exception as e:
        print(f"Error during RSA encryption: {e}")
        return None

# 主函数
def main():
    print("--- Starting Mount Setting Request Tool ---")

    # 获取公钥
    print(f"Fetching public key from: {PUBLIC_KEY_URL}")
    public_pem_data = get_public_key(PUBLIC_KEY_URL)
    if public_pem_data is None:
        print("Failed to get public key. Exiting.")
        return

    # 生成随机密钥和IV (AES等对称加密算法的密钥长度)
    encrypt_key_raw = generate_random_bytes(16) 
    encrypt_iv_raw = generate_random_bytes(16)

    print(f"Generated raw encryptKey: {encrypt_key_raw.hex()}")
    print(f"Generated raw encryptIv: {encrypt_iv_raw.hex()}")

    # 使用公钥加密 encryptKey 和 encryptIv
    print("Encrypting encryptKey and encryptIv with public key...")
    encrypted_key = rsa_encrypt(public_pem_data, encrypt_key_raw)
    encrypted_iv = rsa_encrypt(public_pem_data, encrypt_iv_raw)

    if encrypted_key is None or encrypted_iv is None:
        print("Encryption failed. Exiting.")
        return

    # Base64 编码加密后的数据
    encrypt_key_b64 = base64.b64encode(encrypted_key).decode('utf-8')
    encrypt_iv_b64 = base64.b64encode(encrypted_iv).decode('utf-8')

    print(f"Encrypted and Base64 encoded encryptKey: {encrypt_key_b64}")
    print(f"Encrypted and Base64 encoded encryptIv: {encrypt_iv_b64}")

    # 构建请求头
    headers = {
        "Content-Type": "application/json",
        "token": YOUR_AUTH_TOKEN
    }
    if YOUR_AUTH_TOKEN == "YOUR_AUTH_TOKEN_HERE":
        print("WARNING: Authorization token is not set. The request will likely fail.")
        print("Please replace 'YOUR_AUTH_TOKEN_HERE' with your actual token.")

    # 构建请求体
    payload = {
        "groupId": GROUP_ID,
        "encryptKey": encrypt_key_b64,
        "encryptIv": encrypt_iv_b64
    }

    print(f"\nSending POST request to: {API_ENDPOINT}")
    print(f"Request Headers: {json.dumps(headers, indent=2)}")
    print(f"Request Payload: {json.dumps(payload, indent=2)}")

    # 发送 POST 请求
    try:
        response = requests.post(API_ENDPOINT, headers=headers, data=json.dumps(payload))
        response.raise_for_status() # 检查HTTP错误
        
        print("\n--- Request Successful ---")
        print(f"Status Code: {response.status_code}")
        print(f"Response Body: {json.dumps(response.json(), indent=2, ensure_ascii=False)}") # 打印响应
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
        print(f"Response Body: {response.text}")
    except requests.exceptions.RequestException as req_err:
        print(f"Request error occurred: {req_err}")
    except json.JSONDecodeError:
        print("Response was not in JSON format.")
        print(f"Response Body: {response.text}")

if __name__ == "__main__":
    main()