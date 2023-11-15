FROM alpine

COPY natter-check.py /opt/natter-check.py

RUN apk update \
    && apk add python3 \
    && chmod a+x /opt/natter-check.py


ENV HOME        /opt
ENV PATH        /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV LANG        C.UTF-8
ENV LANGUAGE    C.UTF-8
ENV LC_ALL      C.UTF-8

ENTRYPOINT ["/opt/natter-check.py"]
