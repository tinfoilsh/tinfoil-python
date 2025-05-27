"""
Run only when TINFOIL_* environment variables are present.
The job that sets those vars lives in .github/workflows/integration.yml.
"""

import os
import pytest
import asyncio
from pathlib import Path
from tinfoil import TinfoilAI, AsyncTinfoilAI

TEST_AUDIO_PATH = Path(__file__).parent / "jackhammer.wav"
TEST_AUDIO_TEXT = "The stale smell of old beer lingers."
ENCLAVE = "audio-processing.model.tinfoil.sh"
REPO = "tinfoilsh/confidential-audio-processing"

@pytest.fixture(scope="session")
def client() -> TinfoilAI:
    return TinfoilAI(
        enclave=ENCLAVE,
        repo=REPO,
        api_key=os.getenv("TINFOIL_API_KEY", "tinfoil"),
    )


@pytest.fixture(scope="session")
def async_client() -> AsyncTinfoilAI:
    return AsyncTinfoilAI(
        enclave=ENCLAVE,
        repo=REPO,
        api_key=os.getenv("TINFOIL_API_KEY", "tinfoil"),
    )


def test_audio_transcription(client):
    """Test synchronous audio transcription."""
    with open(TEST_AUDIO_PATH, "rb") as audio_file:
        transcription = client.audio.transcriptions.create(
            file=audio_file,
            model="whisper-large-v3-turbo",
        )
    assert transcription.text.strip() == TEST_AUDIO_TEXT
    print(f"Transcription: {transcription.text}")


@pytest.mark.asyncio
async def test_async_audio_transcription(async_client):
    """Test asynchronous audio transcription."""
    with open(TEST_AUDIO_PATH, "rb") as audio_file:
        transcription = await async_client.audio.transcriptions.create(
            file=audio_file,
            model="whisper-large-v3-turbo",
        )
    assert transcription.text.strip() == TEST_AUDIO_TEXT
    print(f"Async Transcription: {transcription.text}")
