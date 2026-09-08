"""
Configurador de Segundo Factor de Autenticacion (2FA / TOTP)
Nube Privada de Camila - Shiori Sentinel v14
"""
import sys
import os
from pathlib import Path

# Agregar raíz al path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.auth import (
    generate_new_totp_secret,
    get_totp_uri,
    verify_totp_code
)
from backend.config import save_2fa_config, is_2fa_enabled, get_2fa_config

def main():
    print("=" * 65)
    print("🔐 CONFIGURADOR DE SEGUNDO FACTOR DE AUTENTICACIÓN (2FA)")
    print("   Nube Privada de Camila — Shiori Sentinel v14")
    print("=" * 65)

    current_cfg = get_2fa_config()
    if current_cfg.get("enabled"):
        print(f"[*] Estado actual: 2FA ACTIVADO (Origen: {current_cfg.get('source')})")
        print(f"[*] Clave actual:  {current_cfg.get('secret')}")
        print("=" * 65)
        ans = input("¿Deseas generar una nueva clave y reemplazar la actual? (s/N): ").strip().lower()
        if ans != "s":
            print("Operación cancelada. El 2FA activo no fue modificado.")
            return

    secret = generate_new_totp_secret()
    otp_uri = get_totp_uri(secret, account_name="Camila")

    print("\n✨ NUEVA CLAVE GENERADA CON ÉXITO:")
    print(f"   Clave Secreta (Base32): {secret}")
    print(f"   URI de Autenticación:  {otp_uri}\n")
    print("Instrucciones para vincular tu teléfono:")
    print("1. Abre Google Authenticator, Microsoft Authenticator, 1Password o Apple Passwords.")
    print("2. Elige 'Ingresar clave de configuración / manual'.")
    print(f"3. Escribe el nombre de cuenta 'Camila' y pega la clave: {secret}")
    print("4. Selecciona tipo 'Basado en tiempo' (TOTP / 30 segundos).")
    print("=" * 65)

    test_code = input("\nIngresa el código de 6 dígitos que muestra tu app para confirmar: ").strip()
    if verify_totp_code(test_code, secret=secret):
        save_2fa_config(secret)
        print("\n🎉 ¡CÓDIGO VERIFICADO CORRECTAMENTE!")
        print("El segundo factor de autenticación ha sido guardado y activado en tu nube.")
    else:
        print("\n❌ Error: El código ingresado no coincide o expiró.")
        print("Verifica la sincronización de reloj de tu móvil e inténtalo de nuevo.")

if __name__ == "__main__":
    main()
