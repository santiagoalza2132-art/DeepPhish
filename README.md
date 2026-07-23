# DeepPhish: AI-Powered Email Analyzer for Phishing Detection

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge&logo=python)
![AI](https://img.shields.io/badge/AI%2FML-Heuristics-red?style=for-the-badge)
![Email Security](https://img.shields.io/badge/Security-Email%20Analysis-orange?style=for-the-badge)
![Docker](https://img.shields.io/badge/Containerization-Docker-blue?style=for-the-badge&logo=docker)

DeepPhish es un **analizador de correos electrónicos avanzado** diseñado para detectar y clasificar intentos de phishing utilizando una combinación de análisis heurístico y, opcionalmente, integración con servicios de inteligencia de amenazas como VirusTotal. Este proyecto es ideal para profesionales de la ciberseguridad, analistas SOC y equipos de respuesta a incidentes que necesitan una herramienta robusta para evaluar la legitimidad de los correos electrónicos.

## Características Principales

-   **Análisis de Cabeceras**: Extrae y analiza información crítica de las cabeceras del correo (remitente, destinatario, fecha).
-   **Extracción de Contenido**: Parsea el cuerpo del correo (texto plano y HTML) para extraer URLs y adjuntos.
-   **Análisis Heurístico**: Evalúa el correo en busca de indicadores comunes de phishing, como:
    -   Dominios del remitente en listas negras o no seguros.
    -   Palabras clave sospechosas en el asunto y el cuerpo del mensaje.
    -   Adjuntos con extensiones peligrosas.
-   **Integración con VirusTotal**: Opcionalmente, verifica la reputación de las URLs extraídas utilizando la API de VirusTotal.
-   **Puntuación de Phishing**: Asigna una puntuación de riesgo y un veredicto final (No Phishing, Sospechoso, Alta Confianza).
-   **Reportes Detallados**: Genera informes JSON con todos los detalles del análisis y los hallazgos.
-   **Dockerizado**: Fácil despliegue y ejecución en cualquier entorno utilizando Docker y Docker Compose.

## Arquitectura

DeepPhish está implementado en Python y utiliza librerías estándar para el procesamiento de correos electrónicos (`email`), análisis de HTML (`BeautifulSoup`) y peticiones HTTP (`requests`). La lógica de análisis se basa en reglas heurísticas configurables y puede extenderse para incluir modelos de Machine Learning para un análisis más sofisticado. Se ejecuta en un contenedor Docker para asegurar un entorno consistente.

## Requisitos

-   Docker y Docker Compose
-   Python 3.9 o superior (dentro del contenedor)
-   (Opcional) Una API Key de VirusTotal para la verificación de URLs.

## Configuración

1.  **Clonar el repositorio**:

    ```bash
git clone https://github.com/santiagoalza2132-art/DeepPhish.git
cd DeepPhish
    ```

2.  **Configurar `config/config.json`**: Edita este archivo para incluir tu API Key de VirusTotal (si la tienes) y una lista de dominios seguros (`safe_domains`) que no deben ser marcados como sospechosos.

    ```json
    {
        "virustotal_api_key": "TU_API_KEY_VIRUSTOTAL",
        "safe_domains": [
            "tu-empresa.com",
            "otro-dominio-seguro.org"
        ]
    }
    ```

3.  **Configurar `data/phishing_indicators.json`**: Personaliza las listas de dominios y palabras clave en lista negra para mejorar la detección.

    ```json
    {
        "blacklisted_domains": [
            "malicious-site.xyz",
            "phishing-bank.com"
        ],
        "blacklisted_keywords": [
            "urgente",
            "verifique su cuenta",
            "premio",
            "ganador"
        ]
    }
    ```

## Uso

1.  **Desplegar con Docker Compose**:

    Para construir la imagen y ejecutar el analizador. Puedes pasar el contenido RAW de un correo electrónico a través de `stdin` o montando un archivo.

    ```bash
docker-compose up --build
    ```

    Luego, para analizar un correo electrónico, puedes usar:

    ```bash
# Ejemplo con un archivo de correo electrónico (crea un archivo email_ejemplo.eml primero)
docker-compose run deepphish python src/deepphish.py email_ejemplo.eml

# O para pasar el contenido directamente (interactivo)
docker-compose run -it deepphish
# Pega el contenido RAW del correo y presiona Ctrl+D
    ```

    DeepPhish generará un reporte `deepphish_report.json` en la carpeta `reports/`.

## Estructura del Proyecto

```
DeepPhish/
├── .github/
│   └── workflows/
│       └── main.yml  # CI/CD para pruebas y despliegue
├── config/
│   └── config.json   # Configuración de API keys y dominios seguros
├── data/
│   └── phishing_indicators.json # Indicadores de phishing (dominios, palabras clave)
├── reports/          # Reportes de análisis generados
├── src/
│   └── deepphish.py    # Lógica principal del analizador
├── Dockerfile        # Define la imagen Docker para DeepPhish
├── docker-compose.yml# Orquesta el servicio Docker
├── .gitignore
├── LICENSE
├── README.md
└── requirements.txt  # Dependencias de Python
```

## Contribución

Las contribuciones son bienvenidas. Si deseas mejorar DeepPhish, por favor, abre un *issue* o envía un *pull request*.

## Licencia

Este proyecto está bajo la licencia MIT. Consulta el archivo `LICENSE` para más detalles.

## Contacto

Para preguntas o comentarios, contacta a [K3I0101](https://github.com/santiagoalza2132-art).
