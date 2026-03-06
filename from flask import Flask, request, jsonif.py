from flask import Flask, request, jsonify
from flask_cors import CORS
from PIL import Image
import pytesseract
import io

# ------------------------------------------------------------
# Flask app setup
# ------------------------------------------------------------
app = Flask(__name__)
CORS(app)  # Allow frontend apps (running on different origins) to call this API


# ------------------------------------------------------------
# Scam detection rules
# We group indicators into categories (tactics) with simple keyword matching.
# ------------------------------------------------------------
SCAM_RULES = {
    "Urgency Pressure": [
        "urgent",
        "immediate action",
        "limited time",
        "act now",
    ],
    "Phishing Attempt": [
        "click link",
        "verify account",
        "login now",
        "reset password",
    ],
    "Authority Impersonation": [
        "bank",
        "scholarship team",
        "government support",
        "it department",
    ],
    "Fear Tactics": [
        "account suspended",
        "payment failure",
        "security alert",
        "unauthorized access",
    ],
}

# Risk points for each keyword hit.
# 4 categories * 4 keywords * 8 points = 128 max before capping.
POINTS_PER_MATCH = 8
MAX_SCORE = 100


def extract_text_from_image(image_file) -> str:
    """
    Extract text from an uploaded image using OCR.

    Parameters:
        image_file: file object from request.files

    Returns:
        Extracted text (string). Returns empty string if OCR fails.
    """
    try:
        image_bytes = image_file.read()
        image = Image.open(io.BytesIO(image_bytes))
        extracted_text = pytesseract.image_to_string(image)
        return extracted_text.strip()
    except Exception:
        # Keep this beginner-friendly: if OCR fails, return empty text
        # instead of crashing the whole request.
        return ""


def analyze_scam_risk(text: str) -> dict:
    """
    Analyze text against scam indicators and produce:
      - risk score (0-100)
      - detected tactics
      - short explanation
    """
    normalized_text = text.lower()

    score = 0
    detected_tactics = []
    matched_indicators = []

    for tactic_name, indicators in SCAM_RULES.items():
        tactic_hit = False
        for indicator in indicators:
            if indicator in normalized_text:
                score += POINTS_PER_MATCH
                matched_indicators.append(indicator)
                tactic_hit = True

        if tactic_hit:
            detected_tactics.append(tactic_name)

    # Cap risk score to 100
    score = min(score, MAX_SCORE)

    # Build a short explanation
    if not matched_indicators:
        explanation = (
            "No strong scam indicators were detected in the provided text, "
            "but always verify unexpected messages before taking action."
        )
    else:
        tactic_text = ", ".join(detected_tactics)
        indicator_preview = ", ".join(matched_indicators[:3])
        explanation = (
            f"Potential scam indicators were found. Detected tactics: {tactic_text}. "
            f"Example suspicious phrases: {indicator_preview}."
        )

    return {
        "risk_score": score,
        "detected_tactics": detected_tactics,
        "explanation": explanation,
    }


@app.route("/analyze", methods=["POST"])
def analyze_message():
    """
    POST /analyze

    Accepts:
      - JSON body with: message_text
      - OR form-data with: message_text
      - Optional form-data file: image

    If image is provided, OCR text is extracted and combined with message_text.
    """
    message_text = ""

    # 1) Read text from JSON or form-data
    if request.is_json:
        json_data = request.get_json(silent=True) or {}
        message_text = (json_data.get("message_text") or "").strip()
    else:
        message_text = (request.form.get("message_text") or "").strip()

    # 2) Read optional image and run OCR
    image_file = request.files.get("image")
    ocr_text = ""
    if image_file and image_file.filename:
        ocr_text = extract_text_from_image(image_file)

    # 3) Combine both text sources
    combined_text = "\n".join(part for part in [message_text, ocr_text] if part).strip()

    if not combined_text:
        return (
            jsonify(
                {
                    "error": "No input provided. Send 'message_text' and/or an image file.",
                }
            ),
            400,
        )

    result = analyze_scam_risk(combined_text)
    return jsonify(result), 200


@app.route("/", methods=["GET"])
def health_check():
    """Simple health endpoint to confirm API is running."""
    return jsonify({"status": "ok", "message": "Student Scam Shield API is running."})


if __name__ == "__main__":
    # Run server in development mode
    # Access at: http://127.0.0.1:5000
    app.run(host="0.0.0.0", port=5000, debug=True)
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.route("/detect", methods=["POST"])
def detect_scam():
    data = request.json
    message = data.get("message")

    if "lottery" in message.lower():
        result = "Scam detected"
    else:
        result = "Looks safe"

    return jsonify({"result": result})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
