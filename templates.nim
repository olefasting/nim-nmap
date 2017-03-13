##xSpecPort data retrieval and test
let myBool = false

var x = 0
for i in winSpecPort:
   let myBool = contains(i, "139")
   echo myBool
   echo winSpecPort[x]
   inc(x)
