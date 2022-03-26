#export CC=/usr/local/clang/bin/clang && export CXX=/usr/local/clang/bin/clang++ \
rm -rf build && mkdir build && cd build && cmake -DCOMPILE_TARGET=DESKTOP_x86_64 -DFLAVOR=DESKTOP ..
