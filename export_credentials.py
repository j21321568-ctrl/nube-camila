"""
Herramienta de utilidad para Despliegue en Render / Railway.
Convierte tu archivo local 'credentials.json' en una sola línea compacta
para pegarla directamente en la variable de entorno GOOGLE_CREDENTIALS_JSON.
"""
import sys
import json
import base64
from pathlib import Path

# Asegurar codificación utf-8 en consolas Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

def main():
    cred_file = Path("credentials.json")
    if not cred_file.exists():
        print("❌ Error: No se encontró 'credentials.json' en este directorio.")
        return

    try:
        with open(cred_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"❌ Error al leer credentials.json: {e}")
        return

    # 1. JSON compacto en una sola línea
    single_line_json = json.dumps(data, separators=(',', ':'))

    # 2. Base64
    b64_str = base64.b64encode(single_line_json.encode("utf-8")).decode("utf-8")

    # Guardar en archivo temporal de exportación
    out_file = Path("render_credentials_ready.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("=== OPCIÓN 1: VARIABLE GOOGLE_CREDENTIALS_JSON (Recomendada) ===\n")
        f.write(single_line_json + "\n\n")
        f.write("=== OPCIÓN 2: VARIABLE GOOGLE_CREDENTIALS_BASE64 ===\n")
        f.write(b64_str + "\n")

    print("\n" + "="*70)
    print("✨ CREDENCIALES PREPARADAS PARA RENDER / RAILWAY ✨")
    print("="*70)
    print(f"\nSe ha generado el archivo: {out_file.name}")
    print("\nInstrucciones para Render:")
    print("1. En tu servicio de Render, ve a la pestaña 'Environment'")
    print("2. Agrega una nueva variable llamada: GOOGLE_CREDENTIALS_JSON")
    print("3. Pega el contenido de la Opción 1 que está dentro de render_credentials_ready.txt")
    print("4. ¡Listo! Tu backend en Render podrá conectarse a Google Drive sin subir el archivo JSON a GitHub.")
    print("="*70 + "\n")

if __name__ == "__main__":
    main()
