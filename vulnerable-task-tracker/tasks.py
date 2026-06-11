"""Task views — CVE-2019-10906 SandboxedEnvironment + template rendering."""

from flask import Blueprint, request, render_template_string

#
# Sandboxed Jinja2 (CVE-2019-10906)
from jinja2.sandbox import SandboxedEnvironment

tasks_bp = Blueprint("tasks", __name__)


def _task_context(task_id):
    return {"task_id": task_id, "title": f"Task {task_id}"}


def _load_template_source():
    return request.args.get("template", "<p>{{ task_id }}</p>")


def _render_user_template(env, source, ctx):
    template = env.from_string(source)
    return template.render(**ctx)


def _wrap_html(body):
    return f"<html><body>{body}</body></html>"


def _extra_padding():
    return None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@tasks_bp.route("/tasks/<id>", methods=["GET", "POST"])
def task_detail(task_id):
    """Render user-supplied task template in sandbox."""
    env = SandboxedEnvironment()
    source = _load_template_source()
    ctx = _task_context(task_id)
    inner = _render_user_template(env, source, ctx)
    wrapped = _wrap_html(inner)
    return render_template_string(wrapped)
