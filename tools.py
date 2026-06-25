def lookup_threat_intel(domain_or_ip: str) -> dict:
    return {"result": "no match found", "source": "mock"}


def get_cve_detail(cve_id: str) -> dict:
    return {"result": "no match found", "source": "mock"}


def search_known_malware_signature(signature_name: str) -> dict:
    return {"result": "no match found", "source": "mock"}


AVAILABLE_TOOLS = {
    "lookup_threat_intel": lookup_threat_intel,
    "get_cve_detail": get_cve_detail,
    "search_known_malware_signature": search_known_malware_signature,
}

TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "lookup_threat_intel",
            "description": "CTI 데이터베이스에서 도메인 또는 IP의 위협 정보를 조회한다. 알려진 악성 여부, 관련 캠페인, 태그 등을 반환.",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain_or_ip": {
                        "type": "string",
                        "description": "조회할 도메인 또는 IP 주소",
                    }
                },
                "required": ["domain_or_ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_cve_detail",
            "description": "CVE ID로 취약점 상세 정보를 조회한다. 영향받는 소프트웨어, CVSS 점수, 공격 벡터 등을 반환.",
            "parameters": {
                "type": "object",
                "properties": {
                    "cve_id": {
                        "type": "string",
                        "description": "CVE ID (예: CVE-2021-44228)",
                    }
                },
                "required": ["cve_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_known_malware_signature",
            "description": "시그니처 이름이 알려진 멀웨어/RAT 악용 사례와 연관 있는지 검색한다. 관련 멀웨어 패밀리, 공격 기법, 알려진 IoC 등을 반환.",
            "parameters": {
                "type": "object",
                "properties": {
                    "signature_name": {
                        "type": "string",
                        "description": "Suricata/Snort 시그니처 이름",
                    }
                },
                "required": ["signature_name"],
            },
        },
    },
]
