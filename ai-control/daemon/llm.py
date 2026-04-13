"""
llm.py - Local LLM inference controller for AI Control Daemon

Provides endpoints for local AI model management and inference.
Uses llama-cpp-python for GGUF model loading when available.
Gracefully degrades to stub responses when no model is loaded.
"""

import gc
import os
import asyncio
import logging
from typing import Optional, AsyncGenerator

logger = logging.getLogger("ai-control.llm")

# Global state
_model = None
_model_path = None
_model_lock: asyncio.Lock | None = None
_model_lock_init = False  # guards one-time initialization


def _get_lock():
    global _model_lock, _model_lock_init
    if not _model_lock_init:
        # Safe: first call happens in async context before any concurrent use.
        # asyncio.Lock() must be created within a running event loop.
        _model_lock = asyncio.Lock()
        _model_lock_init = True
    return _model_lock


def get_model_dir() -> str:
    """Get the directory where models are stored."""
    return os.environ.get("AI_MODEL_DIR", "/var/lib/ai-control/models")


def list_models() -> list:
    """List available GGUF models."""
    model_dir = get_model_dir()
    if not os.path.isdir(model_dir):
        return []
    models = []
    for f in os.listdir(model_dir):
        if f.endswith(".gguf"):
            path = os.path.join(model_dir, f)
            size_mb = os.path.getsize(path) / (1024 * 1024)
            models.append({"name": f, "path": path, "size_mb": round(size_mb, 1)})
    return models


async def load_model(model_path: str, n_ctx: int = 2048, n_gpu_layers: int = -1) -> dict:
    """Load a GGUF model for inference."""
    global _model, _model_path

    async with _get_lock():
        try:
            from llama_cpp import Llama
        except ImportError:
            return {"status": "error", "message": "llama-cpp-python not installed"}

        if _model is not None:
            del _model
            _model = None

        try:
            _model = await asyncio.get_running_loop().run_in_executor(
                None, lambda: Llama(
                    model_path=model_path,
                    n_ctx=n_ctx,
                    n_gpu_layers=n_gpu_layers,
                    verbose=False,
                ))
            _model_path = model_path
            logger.info(f"Loaded model: {model_path}")
            return {"status": "ok", "model": os.path.basename(model_path)}
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return {"status": "error", "message": str(e)}


async def unload_model() -> dict:
    """Unload the current model."""
    global _model, _model_path
    async with _get_lock():
        if _model:
            del _model
            _model = None
            _model_path = None
            gc.collect()  # promptly free VRAM / mmap'd weights
        return {"status": "ok"}


def get_status() -> dict:
    """Get LLM subsystem status."""
    try:
        import llama_cpp
        llama_available = True
        llama_version = getattr(llama_cpp, "__version__", "unknown")
    except ImportError:
        llama_available = False
        llama_version = None

    return {
        "llama_cpp_available": llama_available,
        "llama_cpp_version": llama_version,
        "model_loaded": _model is not None,
        "model_path": _model_path,
        "models_dir": get_model_dir(),
        "available_models": list_models(),
    }


async def query(prompt: str, max_tokens: int = 512, temperature: float = 0.7,
                stop: Optional[list] = None) -> dict:
    """Run inference on the loaded model."""
    async with _get_lock():
        if _model is None:
            return {
                "status": "error",
                "message": "No model loaded. Download a GGUF model to " + get_model_dir()
            }

        try:
            model_ref = _model  # Hold reference under lock
            result = await asyncio.get_running_loop().run_in_executor(
                None, lambda: model_ref(
                    prompt,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    stop=stop or [],
                ))
            text = result["choices"][0]["text"] if result.get("choices") else ""
            return {
                "status": "ok",
                "text": text,
                "usage": result.get("usage", {}),
            }
        except Exception as e:
            logger.error(f"Inference error: {e}")
            return {"status": "error", "message": str(e)}


async def query_stream(prompt: str, max_tokens: int = 512,
                       temperature: float = 0.7) -> AsyncGenerator[str, None]:
    """Stream inference tokens."""
    if _model is None:
        yield '{"error": "No model loaded"}'
        return

    # Grab a reference under the lock so unload_model() can't delete it mid-stream
    async with _get_lock():
        model_ref = _model
        if model_ref is None:
            yield '{"error": "No model loaded"}'
            return

    try:
        loop = asyncio.get_running_loop()
        stream = await loop.run_in_executor(
            None, lambda: model_ref(
                prompt, max_tokens=max_tokens, temperature=temperature, stream=True
            ))
        # Each next() on the stream blocks until the next token is ready,
        # so we must run iteration in the executor to avoid blocking the loop.
        _sentinel = object()
        stream_iter = iter(stream)
        while True:
            chunk = await loop.run_in_executor(
                None, lambda: next(stream_iter, _sentinel))
            if chunk is _sentinel:
                break
            token = chunk["choices"][0].get("text", "")
            if token:
                yield token
    except Exception as e:
        yield f'{{"error": "{str(e)}"}}'
