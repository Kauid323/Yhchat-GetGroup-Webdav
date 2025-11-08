import os
import base64
import json
import requests
import xml.etree.ElementTree as ET
from urllib.parse import urljoin
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ====== 配置 ======
API_URL = "https://chat-go.jwzhd.com/v1/mount-setting/list"
GROUP_ID = "748861156" // 群聊id
TOKEN = "" // 用户token

PUBLIC_KEY_PEM = """-----BEGIN RSA PUBLIC KEY-----
MIICCgKCAgEA5MSOx8O11qDYdmR40FUs3a0gjdEzQOfHJFVlSilg83sbl65D3alh
SDfP1h52dbr8m1XmQkjUaTCXfAGdN2p3M6wR6H7pniuHjSzXyPq7ZhmXxFa9dNeR
YDgePFVlLzBYEklYWa2YQ+bu2QRU3h2I94Go91vWVL9KEFe2fi1sfaycyU8h5DS5
D7f3SAtg1L2kcLU+2kfzF5XTyXJUlo0DkdV38BXq0gPqURiEscBRM5K5WF73xJfc
rUcPfDSp1OP8itTNPdgEUC8H1tEPnWhMC7vDNPxuGZ2dGXhedMuO9KW/QmdZ9qi1
5W+ZXdUQdKmTo/V8Z5gDxjWW3/LC6/PexS9HeIyuoLgYWd1GtOcl19FhvipM2Wuv
UjJvwUOqlyPa/MR8e5z5P2J4DEd74QSHaCuNHHDOZMuJWtNGcirXpzo0a41rwpfz
lo4SrzberFL1dl361OewJkqq4fg5dfGgGZcPTxZ+WxVWpmMSlimrpRNcZNy8+orn
iRRhVTW6cXvaku2HlSZGvI+7eoHIYaE0YcOzMzdODTKYl33FSbRRIn2ly0bfqoMd
192qmGAkPa7eqdI0FZSjHmRxc2DEXOq9A6BpJGq0zyVhoyGvfVc88qAh4gwGzvx/
yQGy3WJ+xqP1aUJardDi1g5VPLp0jQcg7k0QP98NfxhdOb2jiH0ClkcCAwEAAQ==
-----END RSA PUBLIC KEY-----"""

# ====== 加密/解密工具 ======
def load_rsa_public_key(pem_str):
    return serialization.load_pem_public_key(pem_str.encode())

def rsa_encrypt(public_key, data: bytes) -> str:
    encrypted = public_key.encrypt(data, padding.PKCS1v15())
    return base64.b64encode(encrypted).decode()

def aes_decrypt(ciphertext_b64, key, iv):
    ciphertext = base64.b64decode(ciphertext_b64)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted

def unpad_pkcs7(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        return data
    return data[:-pad_len]

# ====== WebDAV 客户端 ======
class WebDAVClient:
    def __init__(self, base_url, username, password, auth_type='basic'):
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.auth_type = auth_type.lower()
        self.session = requests.Session()

    def _auth_header(self):
        if self.auth_type == 'basic':
            token = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
            return {'Authorization': f'Basic {token}'}
        return {}

    def _full_url(self, path):
        return urljoin(self.base_url + '/', path.lstrip('/'))

    def propfind(self, path, depth=1):
        url = self._full_url(path)
        headers = {
            'Depth': str(depth),
            'Content-Type': 'application/xml',
        }
        headers.update(self._auth_header())
        body = '''<?xml version="1.0"?>
<d:propfind xmlns:d="DAV:">
  <d:prop>
    <d:displayname/>
    <d:resourcetype/>
    <d:getcontentlength/>
    <d:getcontenttype/>
    <d:getetag/>
    <d:getlastmodified/>
  </d:prop>
</d:propfind>'''
        response = self.session.request('PROPFIND', url, headers=headers,
                                        data=body,
                                        auth=(self.username, self.password) if self.auth_type == 'digest' else None)
        response.raise_for_status()
        return self._parse_propfind(response.text)

    def _parse_propfind(self, xml_text):
        ns = {'d': 'DAV:'}
        root = ET.fromstring(xml_text)
        items = []
        for response in root.findall('d:response', ns):
            href = response.find('d:href', ns).text
            props = response.find('d:propstat/d:prop', ns)
            item = {
                'href': href,
                'displayname': props.findtext('d:displayname', default='', namespaces=ns),
                'contenttype': props.findtext('d:getcontenttype', default='', namespaces=ns),
                'contentlength': props.findtext('d:getcontentlength', default='', namespaces=ns),
                'lastmodified': props.findtext('d:getlastmodified', default='', namespaces=ns),
                'etag': props.findtext('d:getetag', default='', namespaces=ns),
                'is_collection': props.find('d:resourcetype/d:collection', ns) is not None
            }
            items.append(item)
        return items

# ====== 主流程 ======
def main():
    key = os.urandom(16)
    iv = os.urandom(16)
    pubkey = load_rsa_public_key(PUBLIC_KEY_PEM)
    enc_key = rsa_encrypt(pubkey, key)
    enc_iv = rsa_encrypt(pubkey, iv)

    headers = {
        "token": TOKEN,
        "Content-Type": "application/json"
    }

    payload = {
        "encryptKey": enc_key,
        "encryptIv": enc_iv,
        "groupId": GROUP_ID
    }

    try:
        resp = requests.post(API_URL, json=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print("❌ 请求失败:", e)
        return

    print("📦 原始响应体：")
    print(json.dumps(data, indent=2, ensure_ascii=False))

    if data.get("code") != 1:
        print("❌ 接口返回错误:", data.get("msg"))
        return

    for i, item in enumerate(data["data"]["list"], 1):
        try:
            enc_pwd = item["webdavPassword"]
            raw = aes_decrypt(enc_pwd, key, iv)
            clean_pwd = unpad_pkcs7(raw).decode(errors='ignore')
            print(f"\n🔐 第 {i} 个 WebDAV 配置：")
            print(f"📂 URL: {item['webdavUrl']}")
            print(f"👤 用户名: {item['webdavUserName']}")
            print(f"🔑 密码: {clean_pwd}")

            # 自动登录 WebDAV 并列出目录
            client = WebDAVClient(
                base_url=item["webdavUrl"],
                username=item["webdavUserName"],
                password=clean_pwd,
                auth_type='digest'  # 可改为 'basic' 视服务端支持情况
            )
            print("📁 远程目录内容：")
            items = client.propfind(item.get("webdavRootPath", "/"))
            for entry in items:
                print(f" - {entry['displayname']} ({'文件夹' if entry['is_collection'] else '文件'})")
        except Exception as e:
            print(f"⚠️ 第 {i} 个配置处理失败: {e}")

# ====== 执行 ======
if __name__ == "__main__":
    main()
