UNAME_S = $(shell uname -s)

OBJ = main.o interpret.o sun4m.o esp.o scsi.o disassemble.o loadelf.o helper.o sparse_mem.o ckpt.o

ifeq ($(UNAME_S),Linux)
	CXX = clang++-20 -march=native -flto
	EXTRA_LD = -lboost_program_options -lboost_serialization -lcapstone
endif

ifeq ($(UNAME_S),FreeBSD)
	CXX = CC -march=native
	EXTRA_LD = -L/usr/local/lib -lboost_program_options -lcapstone
endif

ifeq ($(UNAME_S),Darwin)
	CXX = clang++ -march=native -flto -I/opt/local/include
	EXTRA_LD = -L/opt/local/lib -lboost_program_options-mt -lboost_serialization-mt -lcapstone
endif

CXXFLAGS = -std=c++17 -g $(OPT)
LIBS =  $(EXTRA_LD) -lpthread

DEP = $(OBJ:.o=.d)
OPT = -O3 -g -fomit-frame-pointer
EXE = ss10sim

.PHONY : all clean

# first rule = default goal
all: $(EXE)

$(EXE) : $(OBJ)
	$(CXX) $(CXXFLAGS) $(OBJ) $(LIBS) -o $(EXE)

%.o: %.cc
	$(CXX) -MMD $(CXXFLAGS) -c $<

-include $(DEP)

clean:
	rm -rf $(EXE) $(OBJ) $(DEP)
