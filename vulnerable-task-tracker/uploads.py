"""Uploads — CVE-2020-5313 PIL.Image.open."""

from flask import Blueprint, request
from PIL import Image

uploads_bp = Blueprint("uploads", __name__)


def _get_upload_stream():
    f = request.files.get("file")
    if not f:
        return None
    return f.stream


def _image_metadata(img):
    return {"width": img.size[0], "height": img.size[1]}


def _save_placeholder(task_id, img):
    return {"task_id": task_id, "saved": True}


def _pad_a():
    return None


def _pad_b():
    return None


def _pad_c():
    return None


def _pad_d():
    return None


def _pad_e():
    return None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@uploads_bp.route("/tasks/<id>/upload", methods=["POST"])
def upload_task_image(task_id):
    stream = _get_upload_stream()
    if stream is None:
        return {"error": "no file"}, 400
    img = Image.open(stream)
    meta = _image_metadata(img)
    _save_placeholder(task_id, img)
    return {"task_id": task_id, **meta}
