FROM python:3.10

ARG GITLAB_TOKEN_USER
ARG GITLAB_TOKEN

RUN mkdir -p /usr/src/app

WORKDIR /usr/src/app
ADD requirements.txt /usr/src/app

RUN sed -i -e 's/git+https:\/\/repository.v2.moon-cloud.eu\/dev\/driver.git/git+https:\/\/${GITLAB_TOKEN_USER}:${GITLAB_TOKEN}@repository.v2.moon-cloud.eu\/dev\/driver.git/' requirements.txt

RUN pip install --no-cache-dir -r requirements.txt

ADD probe/schema.json /etc/probe/schema.json
ADD . /usr/src/app

ENTRYPOINT ["/bin/bash", "-c"]
CMD ["/usr/src/app/probe/probe.py"]