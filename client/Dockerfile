FROM python:3.9
ENV PYTHONUNBUFFERED=1
# RUN apk update && apk add postgresql-dev gcc python3-dev musl-dev
ENV PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt requirements.txt
RUN pip3 install --upgrade pip
RUN pip3 install -r requirements.txt
COPY . /app
RUN mkdir /app/data
EXPOSE 5555
CMD ["python3", "client-scheduler.py", "--source", "tenable"]
