CXX ?= c++
CXXFLAGS ?= -std=c++20 -O2 -Wall -Wextra -pedantic -pthread

TARGET = passmgr
SRC = passmgr.cpp vendor/botan/botan_all.cpp

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) -o $(TARGET)

clean:
	rm -f $(TARGET)
