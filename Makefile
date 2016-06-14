CPPFLAGS=-Wall -DNDEBUG -g2 -I$(HELIB)#-O3
LIBS=$(HELIB)/fhe.a -lntl -lgmp -lm
TARGET=simpleSum

.PHONY: all clean

all: $(TARGET)

$(TARGET): main.cpp
	g++ $(CPPFLAGS) $< -o $(TARGET) $(LIBS)

clean:
	rm -f $(TARGET)
