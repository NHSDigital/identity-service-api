FROM alpine:3.12 as base
RUN apk add --no-cache gcc python3-dev py-pip musl-dev make
RUN pip install -U setuptools pip

COPY requirements.txt .

RUN python3 -m pip install -r requirements.txt
COPY app app

EXPOSE 80

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "80"]
