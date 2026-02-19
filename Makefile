# Makefile for phnx

CXX = g++
CXXFLAGS = -O3 -Wall -Wextra -std=c++17 -march=native -g -static
TARGET = phnx
SRC = phnx.cpp

# Windows cross-compile
MINGW_CXX = x86_64-w64-mingw32-g++
WIN_TARGET = phnx.exe

.PHONY: all clean test windows

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC)

windows: $(SRC) $(HEADERS)
	$(MINGW_CXX) $(CXXFLAGS) -o $(WIN_TARGET) $(SRC)

clean:
	rm -f LICENSE.tmp*

test: $(TARGET) test1 test2 test3 test4

test1:
	cp LICENSE.encrypted-2c35a548 LICENSE.tmp1.encrypted-2c35a548
	PHNX_PASSWORD=fourwordsalluppercase ./phnx LICENSE.tmp1.encrypted-2c35a548
	@if diff -q LICENSE LICENSE.tmp1; then \
		echo "Test 1 PASSED"; \
	else \
		echo "Test 1 FAILED"; \
		exit 1; \
	fi

test2:
	cp LICENSE.encrypted LICENSE.tmp2.encrypted
	PHNX_PASSWORD=fourwordsalluppercase ./phnx LICENSE.tmp2.encrypted
	diff LICENSE LICENSE.tmp2
	@if diff -q LICENSE LICENSE.tmp2; then \
		echo "Test 2 PASSED"; \
	else \
		echo "Test 2 FAILED"; \
		exit 1; \
	fi


test3:
	cp LICENSE LICENSE.tmp3
	PHNX_PASSWORD=fourwordsalluppercase ./phnx -c LICENSE.tmp3
	PHNX_PASSWORD=fourwordsalluppercase ./phnx LICENSE.tmp3.encrypted
	@if diff -q LICENSE LICENSE.tmp3; then \
		echo "Test 3 PASSED"; \
	else \
		echo "Test 3 FAILED"; \
		exit 1; \
	fi

test4:
	cp LICENSE LICENSE.tmp4
	PHNX_PASSWORD=fourwordsalluppercase ./phnx LICENSE.tmp4
	rm LICENSE.tmp4.phnx_A LICENSE.tmp4
	PHNX_PASSWORD=fourwordsalluppercase ./phnx LICENSE.tmp4.phnx_F
	@if diff -q LICENSE LICENSE.tmp4; then \
		echo "Test 4 PASSED"; \
	else \
		echo "Test 4 FAILED"; \
		exit 1; \
	fi

install: $(TARGET)
	install -m 0755 $(TARGET) /usr/local/bin/

.DEFAULT_GOAL := all
