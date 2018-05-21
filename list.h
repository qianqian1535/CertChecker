/* * * * * * *
 * Module for creating and manipulating singly-linked lists containing data
 * of any type
 *
 * created for COMP20007 Design of Algorithms - Assignment 1, 2018
 * by Matt Farrugia <matt.farrugia@unimelb.edu.au>
 */

#ifndef LIST_H
#define LIST_H

#include <stdbool.h>

/*                         DO NOT CHANGE THIS FILE
 *
 * DO NOT modify the structs, types or function prototypes defined in this file.
 *
 * We will test your assignment with an unmodified version of this file. Any
 * changes you make will be lost. This may lead to compile errors.
 */


// a list node points to the next node in the list, and to some data
// these values can be used, but should not be *modified* outside of list.c.
// they are read-only!
typedef struct node Node;
struct node {
	Node *next; // pointer to the next node in the list
				// NULL if there is no next node (the last node in the list)
	char *name;
	char *url;
	bool valid;
};

// a list points to its first and last nodes, and stores its size (num. nodes)
// these values can be used, but should not be *modified* outside of list.c.
// they are read-only!
typedef struct list List;
struct list {
	Node *head; // pointer to the first node in the list
	Node *last; // pointer to the last node in the list
	int size;	// number of nodes currently in the list
};


// create a new, empty list and return its pointer
List *new_list();

// destroy a list and free its memory
// DOES NOT FREE POINTERS TO DATA HELD IN THE LISTS NODES, only frees the nodes
void free_list(List *list);


// add an element to the back of a list
// this operation is O(1)
void list_add_end(List* list, char *name, char *url);

void free_word_list(List *list);

// return the number of elements contained in a list
int list_size(List *list);

// returns whether the list contains no elements (true) or some elements (false)
bool list_is_empty(List *list);

#endif
