import time

## In this project, I created a 3x3 puzzle game solver, which will take in a list of input,
## then check if it's possible, move the puzzle so it would end up with a list of ascending order number.
## i.e.: [6,7,5,4,3,0,2,1,8] to [0,1,2,3,4,5,6,7,8], it'll return in form of a 3x3 puzzle when 0 is movable

## Defining Node
class Node:
    def __init__(self, puzzle):
        self.children = []
        self.parent = None
        self.puzzle = puzzle[:]
        self.zero = 0

## Create child of the main Node to make movement
    def create_child(self, puzzle):
        child = Node(puzzle)
        self.children.append(child)
        child.parent = self

## Move right function
    def move_right(self):
        if (self.zero + 1) % 3 != 0:  # Check if move is possilbe
            pc = self.puzzle[:]  # Create new puzzle for child
            pc[self.zero], pc[self.zero + 1] = pc[self.zero +
                                                  1], pc[self.zero]  # Swap tile positions
            self.create_child(pc)  # Create new child

## Move left function
    def move_left(self):
        if self.zero % 3 != 0:
            pc = self.puzzle[:]
            pc[self.zero], pc[self.zero - 1] = pc[self.zero - 1], pc[self.zero]
            self.create_child(pc)

## Move up function
    def move_up(self):
        if self.zero > 2:
            pc = self.puzzle[:]
            pc[self.zero], pc[self.zero - 3] = pc[self.zero - 3], pc[self.zero]
            self.create_child(pc)

## Move down function
    def move_down(self):
        if self.zero < 6:
            pc = self.puzzle[:]
            pc[self.zero], pc[self.zero + 3] = pc[self.zero + 3], pc[self.zero]
            self.create_child(pc)

## Test if the goal is reachable            
    def goaltest(self):
        isGoal = True
        # itterate over length of puzzle, if isn't solved, return false
        for i in range(len(self.puzzle)):
            if i != self.puzzle[i]:
                isGoal = False
                return isGoal
        return isGoal

## Check if the node is movable
    def expand_node(self):  # Check all neighboring nodes
        for i in range(len(self.puzzle)):  # Save current index of Zero tile
            if self.puzzle[i] == 0:
                self.zero = i
        self.move_right()
        self.move_down()
        self.move_left()
        self.move_up()

## Check if the puzzle is solvable        
    def is_unsolvable(self):  # explain from https://math.stackexchange.com/questions/293527/how-to-check-if-a-8-puzzle-is-solvable/1402737#1402737
        print(self.puzzle)
        count = 0
        for i in range(8):
            for j in range(i, 9):
                if self.puzzle[i] > self.puzzle[j] and self.puzzle[j] != 0:
                    count += 1
        if count % 2 == 1:
            return True
        else:
            return False

## Print out the puzzle
    def printPuzzle(self):  # CHANGE TO VISUALIZER
        print()
        m = 0
        for i in range(3):
            for j in range(3):
                print(self.puzzle[m], end=" ")
                m += 1
            print()

            

class search:
    def __init__(self):
        pass

## Using breadth-First Search
    def breadthFirstSearch(self, root):
        openlist = []
        visited = set()
        openlist.append(root)  # Add root to open list
        visited.add(tuple(root.puzzle))

        while(True):
            current_Node = openlist.pop(0)
            if current_Node.goaltest():  # check if current depth sort completed, if true...
                pathtosolution = search.pathtrace(
                    current_Node)  # set path solution
                print(len(visited))  # print number of nodes visited
                return pathtosolution

            current_Node.expand_node()  # expand to neighbouring nodes

            for current_child in current_Node.children:  # for child in neighboring children
                # if neighbouring child hasn't previously been visited
                if (not (tuple(current_child.puzzle) in visited)):
                    # add neighbouring child to open list
                    openlist.append(current_child)
                    # add current child to visited list
                    visited.add(tuple(current_child.puzzle))

## Trace the path
    def pathtrace(n):
        current = n
        path = []
        path.append(current)
        while current.parent != None:  # get parent node of child nodes until you reach the root node where current.parent is None
            current = current.parent
            path.append(current)
        return path


## Input puzzle
if __name__ == "__main__":
    # puzzle = [int(x) for x in input().split()]
    puzzle = [6, 7, 5, 4, 3, 0, 2, 1, 8] ## Can change for different puzzle
    root = Node(puzzle)
    if root.is_unsolvable():
        print("No solution Found")

    else:
        s = search()

        print("Finding Solution")
        start = time.time()

        solution = s.breadthFirstSearch(root)
        end = time.time()
        solution.reverse()
        for i in range(len(solution)):
            solution[i].printPuzzle()
        print("Number of steps taken: ", len(solution))
        print("Time Taken: ", round(end-start, 2))
