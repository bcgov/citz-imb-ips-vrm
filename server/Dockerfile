FROM python:3.9
ENV PYTHONUNBUFFERED=1
## RUN apk update && apk add postgresql-dev gcc python3-dev musl-dev
ENV PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt requirements.txt
RUN pip3 install --upgrade pip
RUN pip3 install -r requirements.txt
COPY . /app
# RUN mkdir /app/data
# RUN mkdir /app/data/vrm_list
EXPOSE 5555
# Run web.py
CMD ["python3", "web.py"]
