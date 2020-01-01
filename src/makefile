CC = g++
CFLAGS := -fPIC -std=c++11 -Wall -g
LDFLAGS := -fPIC -shared

TARGET = libbase32.so
INC_PATH += 
STATIC_LIBS +=
STATIC_LIB_PATH +=
LIBS += 
LIB_PATH +=

sources = base32.cpp

objects := $(patsubst %.cpp, %.o, $(sources))
objects := $(patsubst %.cc, %.o, $(objects))
objects := $(patsubst %.c, %.o, $(objects))
all : $(TARGET)
	@echo "make done"
%.o : %.cpp
	$(CC) $(CFLAGS) $(DEFINES) $(INC_PATH) -c $< -o $@
%.o : %.cc
	$(CC) $(CFLAGS) $(DEFINES) $(INC_PATH) -c $< -o $@
%.o : %.c
	$(CC) $(CFLAGS) $(DEFINES) $(INC_PATH) -c $< -o $@

$(TARGET) : $(objects)
	$(CC) $(LDFLAGS) $^ -Wl,-Bstatic $(STATIC_LIBS) $(STATIC_LIB_PATH) -Wl,-Bdynamic $(LIBS) $(LIB_PATH) -o $@

clean :
	-rm -rf *.o $(TARGET)