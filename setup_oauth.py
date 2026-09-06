"""
Asistente de Configuración OAuth 2.0 (Para cuentas personales @gmail con 15GB)
Permite conectar la Nube Privada de Camila a una cuenta de Google personal
para usar sus 15 GB gratuitos de almacenamiento sin restricciones de Cuentas de Servicio.
"""
import sys
import json
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

def main():
    print("="*70)
    print("   ASISTENTE DE CONEXIÓN OAUTH 2.0 PARA LA NUBE DE CAMILA")
    print("="*70)
    print("\nEste asistente te permite enlazar tu cuenta de Google personal (con tus 400 GB)")
    print("para almacenar todas las fotos, videos y recuerdos de Camila sin restricciones de cuota.\n")

    # Buscar client_secret*.json
    candidate_files = list(Path(".").glob("client_secret*.json"))
    client_secret_file = None

    if candidate_files:
        client_secret_file = candidate_files[0]
        print(f"✅ Se encontró archivo de cliente OAuth: {client_secret_file.name}")
    else:
        print("ℹ️ Para generar tu token OAuth:")
        print("1. Ve a Google Cloud Console (https://console.cloud.google.com/)")
        print("2. En 'APIs y Servicios' > 'Credenciales', haz clic en '+ Crear Credenciales' > 'ID de cliente de OAuth'")
        print("3. Selecciona 'Aplicación de escritorio' y dale el nombre 'Camila Cloud Desktop'")
        print("4. Descarga el archivo JSON y colócalo en esta carpeta con el nombre 'client_secret.json'")
        print("\nSi ya lo tienes, ingresa la ruta del archivo:")
        user_input = input("Ruta de client_secret.json (o Enter para cancelar): ").strip()
        if user_input and Path(user_input).exists():
            client_secret_file = Path(user_input)
        else:
            print("\nOperación cancelada. Puedes ejecutar este script más tarde cuando tengas el archivo.")
            return

    try:
        from google_auth_oauthlib.flow import InstalledAppFlow
    except ImportError:
        print("\n❌ Falta la librería google-auth-oauthlib. Instálala con:")
        print("pip install google-auth-oauthlib")
        return

    # Principio de Mínimo Privilegio (H5): Acotar acceso a solo archivos gestionados por la app
    SCOPES = [os.getenv("GOOGLE_DRIVE_SCOPE", "https://www.googleapis.com/auth/drive.file").strip()]
    flow = InstalledAppFlow.from_client_secrets_file(str(client_secret_file), SCOPES)
    print("\nAbriendo navegador para autorizar acceso a Google Drive...")
    creds = flow.run_local_server(port=8080)

    token_dict = {
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri": creds.token_uri,
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "scopes": creds.scopes
    }

    # Guardar localmente en oauth_token.json
    with open("oauth_token.json", "w", encoding="utf-8") as f:
        json.dump(token_dict, f, indent=2)

    # Preparar para Render
    oneline_oauth = json.dumps(token_dict, separators=(',', ':'))
    with open("render_oauth_ready.txt", "w", encoding="utf-8") as f:
        f.write(oneline_oauth)

    print("\n" + "="*70)
    print("✨ ¡AUTORIZACIÓN COMPLETADA CON ÉXITO! ✨")
    print("="*70)
    print("Se ha generado el archivo 'oauth_token.json'.")
    print("Tu backend ahora utilizará tu cuota de 15 GB gratuita para guardar los archivos de Camila.")
    print("También se generó 'render_oauth_ready.txt' para que puedas copiarlo a la variable")
    print("GOOGLE_OAUTH_TOKEN en Render si deseas desplegarlo allí.")
    print("="*70 + "\n")

if __name__ == "__main__":
    main()
