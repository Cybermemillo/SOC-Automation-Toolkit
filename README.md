# SOC Automation Toolkit (Python)

Herramienta modular para automatización y análisis Blue Team. Permite:

- Ingestar y parsear logs (Syslog, JSON)
- Detectar patrones sospechosos mediante reglas simples
- Verificar IOCs usando listas locales o APIs externas
- Generar reportes (Markdown, HTML, JSON)
- Simular acciones de respuesta (bloqueo de IP, webhook)

## Estructura del proyecto

soc-toolkit/
├─ .vscode
│  ├─ settings.json
│  └─ launch.json
├─ src/
│  ├─ __init__.py
│  ├─ main.py
│  ├─ parser.py
│  ├─ ioc_checker.py
│  ├─ detector.py
│  ├─ reporter.py
│  └─ responder.py
├─ tests/
│  ├─ test_parser.py
│  └─ test_ioc_checker.py
├─ sample_data/
│  ├─ wazuh_sample.json
│  └─ syslog_sample.log
├─ config.yml
├─ requirements.txt
└─ README.md

## Instalación

1. Clonar el repositorio:
   git clone https://github.com/Cybermemillo/SOC-Automation-Toolkit.git

   cd soc-toolkit
2. Crear entorno virtual:
   python -m venv .venv
   source .venv/bin/activate    # Linux/macOS
   .venv\Scripts\activate       # Windows
3. Instalar dependencias:
   pip install -r requirements.txt

## Uso rápido

Ejecutar el script principal:
   python src/main.py --input sample_data/wazuh_sample.json --output report.json

## Roadmap

- [ ] Ingesta de logs CSV y JSON
- [ ] Reglas de detección configurables
- [ ] Verificación de IOCs con APIs externas
- [ ] Reportes HTML y Markdown
- [ ] Respuesta automática simulada
- [ ] Integración con SOAR mediante export JSON

## Licencia

MIT License.
