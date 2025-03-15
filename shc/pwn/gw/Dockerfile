FROM i386/ubuntu:18.04

RUN apt-get update
RUN apt-get install -y python3-pip python3-dev git libssl-dev libffi-dev \
                       gdb git wget vim locales socat lsof \
                       build-essential pkg-config rustc cargo libssl-dev
RUN python3 -m pip install --upgrade pip
RUN pip install --upgrade pip
RUN python3 -m pip install --upgrade pwntools
RUN git clone --branch 2023.07.17 https://github.com/pwndbg/pwndbg  ~/pwndbg
RUN cd ~/pwndbg && ./setup.sh
RUN echo "set startup-quietly on" >~/.gdbearlyinit
RUN echo "source ~/pwndbg/gdbinit.py\n\
set show-tips off\n\
set max-visualize-chunk-size 192\n\
set debuginfod enabled off\n\
set breakpoint pending on\n" >~/.gdbinit
RUN echo "export LC_CTYPE=C.UTF-8" >>~/.bashrc
RUN apt-get install -y lsof

COPY GW /root
COPY filter.py /root
RUN chmod +x /root/GW
ENTRYPOINT ["/bin/bash"]
EXPOSE 8080
