rm -rf build
mkdir build
cd build
cmake -DCMAKE_PREFIX_PATH="/home/jkulskis/dev/sdr" ..
make
sudo make install
cd ..
