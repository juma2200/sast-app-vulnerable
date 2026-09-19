# App Flask vulnerable (ejercicio SAST On-Premise)

Aplicación **deliberadamente insegura** creada solo para practicar análisis
estático de código (SAST). Los problemas intencionales están marcados con
comentarios `[VULN-XX]` (seguridad) y `[CALIDAD-XX]` (calidad) dentro de
`app.py`.

> ⚠️ No desplegar en internet ni en producción. Ejecutar solo en una máquina
> local o de laboratorio.

## Ejecutar

```bash
python -m venv venv
source venv/bin/activate        # En Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

## Analizar con SAST (ejemplo con Bandit)

```bash
pip install bandit
bandit -r . -f html -o reporte_antes.html
```

Luego de corregir el código, volver a ejecutar y comparar:

```bash
bandit -r . -f html -o reporte_despues.html
```
