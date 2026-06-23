# Auditoría Completa Prism v2-exploration

## Estado actual
- Rama: v2-exploration
- Tests: 246 PASSED, 0 FAILED
- Commits: 20 en v2-exploration vs main
- Diff: 11 archivos, +1648/-51 líneas

## Componentes (todos completos)
- parser.py: classify + IOC extract + nature_category
- enricher.py: VT + AbuseIPDB + OTX (con error cache TTL 60s)
- reasoner.py: Ollama qwen2.5:3b (temperatura=0, JSON strict)
- router.py: verdicts → create_case / discard
- logger.py: CSV audit trail (todas las alertas)
- main.py: FastAPI /analyze + orquestación completa

## Output v2 (nuevos campos)
- observables: independent verdict from enrichment
- tags: categorización plana
- key_factors: resumen estructurado
- case_description: narrativa 4-párrafos
- severity_num: 1–4 para TheHive 5
- DEFERRED: correlation_summary, full_description (v2.2 con RAG)

## Fixtures disponibles (7 sintéticas)
- firewall_block.json (public_attack)
- ssh_attack.json (internal_movement)
- virustotal.json, vulnerability.json, windows_logon.json
- windows_spp_error.json, windows_spp_grouped.json (known FPs)

## Objetivo auditoría
1. Ejecutar Prism contra TODAS las fixtures (varias veces cada una)
2. Validar JSON output completo vs schema esperado
3. Medir tiempos (parse, enrich, reason, route, log)
4. Detectar bugs, crashes, comportamientos inesperados
5. Listar oportunidades de mejora antes de Shuffle integration
6. Crear reporte de auditoría con hallazgos + recomendaciones

## Información del entorno
- Python 3.14.5 en venv
- Ollama remoto: qwen2.5:3b (Ubuntu 24.04 server)
- APIs: VirusTotal, AbuseIPDB, OTX (con error cache)
- Dependencias: FastAPI, httpx, requests, etc. (ver requirements.txt)
