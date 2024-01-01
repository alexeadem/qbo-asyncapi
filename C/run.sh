gcc -Wall -lwebsockets test.c -o test
valgrind --error-exitcode=1 --track-origins=yes --leak-check=full ./test
