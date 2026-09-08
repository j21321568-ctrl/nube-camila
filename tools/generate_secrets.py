"""
Generador Criptografico de Secretos para Nube Camila.
Genera claves seguras con entropia suficiente para ACCESS_PASSWORD y SECRET_KEY.
"""
import secrets

def generate():
    secret_key = secrets.token_hex(32)  # 64 caracteres hex = 256 bits reales de entropia
    access_password = secrets.token_urlsafe(16)  # ~22 caracteres de alta entropia
    base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    totp_secret = "".join(secrets.choice(base32_chars) for _ in range(32))  # 160 bits Base32
    
    print("=" * 60)
    print("[*] NUEVOS SECRETOS CRIPTOGRAFICOS GENERADOS")
    print("=" * 60)
    print(f"SECRET_KEY={secret_key}")
    print(f"ACCESS_PASSWORD={access_password}")
    print(f"TOTP_SECRET={totp_secret}")
    print("=" * 60)
    print("Copia estos valores en tu archivo .env local y en las variables de entorno de Render.")
    print("=" * 60)
    return secret_key, access_password, totp_secret

if __name__ == "__main__":
    generate()
