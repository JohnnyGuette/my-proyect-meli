import json
import logging
from google.cloud import logging as cloud_logging
from datetime import datetime, timedelta
import re

def logAnalysisFunction(request):
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger()
    project_id = "my-project-meli-426503"

    client = cloud_logging.Client(project=project_id)
    now = datetime.utcnow()
    past = now - timedelta(days=1)  # 1 día de logs

    now_str = now.isoformat("T") + "Z"
    past_str = past.isoformat("T") + "Z"
    logger.info(f"Obteniendo logs desde {past_str} hasta {now_str}")

    query = f"""
        resource.type="http_load_balancer"
        AND jsonPayload.enforcedSecurityPolicy.name="dvwa-security-policy"
        timestamp >= "{past_str}"
        timestamp <= "{now_str}"
    """

    vulnerabilities = []
    mitigation_actions = []

    entries = list(client.list_entries(order_by=cloud_logging.DESCENDING, filter_=query, page_size=100))

    for entry in entries:
        if isinstance(entry.payload, dict):
            payload = entry.payload
            httpRequest = payload.get('httpRequest', {})
            
            if isinstance(httpRequest, dict):
                requestUrl = httpRequest.get('requestUrl', '')
                requestMethod = httpRequest.get('requestMethod', '')
                requestBody = payload.get('requestBody', '')

                # Patrón de inyección SQL básico
                sql_injection_pattern = r"(?i)id=1(?:'|%27)\+OR\+(?:'|%27)1(?:'|%27)%3D(?:'|%27)1"
                sql_injection_matches = re.findall(sql_injection_pattern, requestUrl)

                if sql_injection_matches or xss_injection_matches:
                    vulnerability_message = f"Solicitud sospechosa: {requestUrl}"
                    if sql_injection_matches:
                        vulnerability_message += " (Posible inyección SQL)"

                    mitigation_action = "Bloquear la solicitud"
                    mitigation_actions.append(mitigation_action)
    response = {
        'vulnerabilities': vulnerabilities,
        'mitigation_actions': mitigation_actions
    }

    logger.info(f"Respuesta generada: {response}")
    return json.dumps(response), 200, {'Content-Type': 'application/json'}