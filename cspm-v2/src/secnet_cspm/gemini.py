import os,json
from google import genai
from google.genai import types
def analyze(finding):
 key=os.getenv("GEMINI_API_KEY")
 if not key: raise RuntimeError("GEMINI_API_KEY is not configured")
 model=os.getenv("GEMINI_MODEL","gemini-2.5-flash")
 client=genai.Client(api_key=key)
 prompt=f"""You are an AWS security analyst advising a CSPM platform.
Analyze ONLY this finding and do not invent AWS state:
{json.dumps(finding,ensure_ascii=False,indent=2)}
Return JSON only with summary, root_cause, impact, recommended_remediation, auto_remediation, verification_steps, confidence, assumptions.
Rules: advisory only; no AWS actions; no credentials; auto_remediation must be SAFE, REVIEW_REQUIRED or MANUAL; confidence 0..1; insufficient context means manual review."""
 r=client.models.generate_content(model=model,contents=prompt,config=types.GenerateContentConfig(temperature=0.1,response_mime_type="application/json"))
 x=json.loads(r.text); x["model"]=model; return x
