FROM itsafeaturemythic/mythic_python_base@sha256:cb309ba1b00e6389d821f2fc3b25b830abad9354626c015975b72005dc001a58

ENV PYTHONDONTWRITEBYTECODE=1

COPY requirements.lock /tmp/nuwa-translation-requirements.lock
RUN python3 -m pip install --no-cache-dir -r /tmp/nuwa-translation-requirements.lock

WORKDIR /Mythic/

CMD ["python3", "main.py"]
