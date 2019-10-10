FROM python
LABEL maintainer="ENOFLAG <mail@enoflag.de>"

# Install python3 and uswgi
RUN apt-get update
RUN apt-get install -y nginx git

# copy our files in.
WORKDIR /checker
COPY ./requirements.txt /checker/requirements.txt
RUN python3 -m pip install -r requirements.txt
COPY . .

ENTRYPOINT ["hypercorn", "-b", ":::80", "-b", "0.0.0.0:80", "-w", "32", "checker:app" ]
