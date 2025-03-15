from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator

#### CIRCUIT #1
c1 = QuantumCircuit(64,64)
# 0
c1.measure(0,0)
c1.barrier()
# 1
c1.measure(1,1)
c1.barrier()
# 5
c1.x(2)
c1.x(3)
c1.x(4)
c1.measure(5,5)
c1.barrier()
# 7
c1.x(3)
c1.x(6)
c1.measure(7,7)
c1.barrier()
# 10
c1.x(8)
c1.x(9)
c1.measure(10,10)
c1.barrier()
# 11
c1.x(9)
c1.measure(11,11)
c1.barrier()
# 13
c1.x(12)
c1.measure(13,13)
c1.barrier()
# 15
c1.x(14)
c1.measure(15,15)
c1.barrier()
# 17
c1.x(16)
c1.measure(17,17)
c1.barrier()
# 19
c1.x(18)
c1.measure(19,19)
c1.barrier()
# 20
c1.measure(20,20)
c1.barrier()
# 23
c1.x(21)
c1.x(22)
c1.measure(23,23)
c1.barrier()
# 25
c1.x(21)
c1.x(24)
c1.measure(25,25)
c1.barrier()
# 29
c1.x(26)
c1.x(27)
c1.x(28)
c1.measure(29,29)
c1.barrier()
# 30
c1.x(27)
c1.measure(30,30)
c1.barrier()
# 31
c1.measure(31,31)
c1.barrier()
# 35
c1.x(32)
c1.x(33)
c1.x(34)
c1.measure(35,35)
c1.barrier()
# 37
c1.x(33)
c1.x(36)
c1.measure(37,37)
c1.barrier()
# 40
c1.x(38)
c1.x(39)
c1.measure(40,40)
c1.barrier()
# 41
c1.x(39)
c1.measure(41,41)
c1.barrier()
# 43
c1.x(42)
c1.measure(43,43)
c1.barrier()
# 45
c1.x(44)
c1.measure(45,45)
c1.barrier()
# 47
c1.x(46)
c1.measure(47,47)
c1.barrier()
# 49
c1.x(48)
c1.measure(49,49)
c1.barrier()
# 50
c1.measure(50,50)
c1.barrier()
# 53
c1.x(51)
c1.x(52)
c1.measure(53,53)
c1.barrier()
# 55
c1.x(51)
c1.x(54)
c1.measure(55,55)
c1.barrier()
# 59
c1.x(56)
c1.x(57)
c1.x(58)
c1.measure(59,59)
c1.barrier()
# 60
c1.x(57)
c1.measure(60,60)
c1.barrier()
# 61
c1.measure(61,61)
c1.barrier()
# two more x'es
c1.x(62)
c1.x(63)
c1.barrier()
# first series of measures
for i in [2,4,6,8,12,14,16,18,22,24,26,28,32,34,36,38,42,44,46,48,52,54,56,58,62]:
  c1.measure(i,i)
  c1.barrier()
# one more x
c1.x(63)
c1.barrier()
# second series of measures
for i in [3,9,21,27,33,39,51,57,63]:
  c1.measure(i,i)
  c1.barrier()


#### CIRCUIT #2
c2 = QuantumCircuit(64,64)
# inputs
for i in [0,1,2,4,6,8,10,11,12,14,16,18,20,21,22,24,26,28,30,31,32,34,36,38,40,41,42,44,46,48,50,51,52,54,56,58,60,61,62]:
  c2.id(i)
# 0
c2.measure(0,0)
c2.barrier()
# 1
c2.measure(1,1)
c2.barrier()
# 10
for i in [2,4,6,8]:
  c2.x(i)
c2.measure(10,10)
c2.barrier()
# 11
c2.swap(2,3)
c2.swap(4,5)
c2.swap(6,7)
c2.swap(8,9)
c2.measure(11,11)
c2.barrier()
# 20
for i in [3,5,7,9]:
  c2.id(i)
for i in [12,14,16,18]:
  c2.x(i)
c2.measure(20,20)
c2.barrier()
# 21
c2.swap(12,13)
c2.swap(14,15)
c2.swap(16,17)
c2.swap(18,19)
c2.measure(21,21)
c2.barrier()
# 30
for i in [13,15,17,19]:
  c2.id(i)
for i in [22,24,26,28]:
  c2.x(i)
c2.measure(30,30)
c2.barrier()
# 31
c2.swap(22,23)
c2.swap(24,25)
c2.swap(26,27)
c2.swap(28,29)
c2.measure(31,31)
c2.barrier()
# 40
for i in [23,25,27,29]:
  c2.id(i)
for i in [32,34,36,38]:
  c2.x(i)
c2.measure(40,40)
c2.barrier()
# 41
c2.swap(32,33)
c2.swap(34,35)
c2.swap(36,37)
c2.swap(38,39)
c2.measure(41,41)
c2.barrier()
# 50
for i in [33,35,37,39]:
  c2.id(i)
for i in [42,44,46,48]:
  c2.x(i)
c2.measure(50,50)
c2.barrier()
# 51
c2.swap(42,43)
c2.swap(44,45)
c2.swap(46,47)
c2.swap(48,49)
c2.measure(51,51)
# 60
for i in [43,45,47,49]:
  c2.id(i)
for i in [52,54,56,58]:
  c2.x(i)
c2.measure(60,60)
c2.barrier()
# 61
c2.swap(52,53)
c2.swap(54,55)
c2.swap(56,57)
c2.swap(58,59)
c2.measure(61,61)
c2.barrier()
# after 61
for i in [53,55,57,59]:
  c2.id(i)
c2.x(62)
# and one more
c2.swap(62,63)
c2.barrier()
# 2-62 measures
for i in [2,4,6,8,12,14,16,18,22,24,26,28,32,34,36,38,42,44,46,48,52,54,56,58,62]:
  c2.measure(i,i)
  c2.barrier()
c2.id(63)
# 3-63 measures
for i in [3,5,7,9,13,15,17,19,23,25,27,29,33,35,37,39,43,45,47,49,53,55,57,59,63]:
  c2.measure(i,i)
  c2.barrier()

#### CIRCUIT #3
c3 = QuantumCircuit(64,64)
# first column of h's
for i in range(64):
  c3.h(i)
c3.barrier()
# 0-9
for i in [0,1,2,3,4,5,6,7,8,9]:
  c3.measure(i,i)
  c3.barrier()
# second column of h's
for i in range (10,64):
  c3.h(i)
# 14
for i in [10,11,12,13]:
  c3.h(i)
c3.measure(14,14)
c3.barrier()
# 18
for i in [10,11,12,13,15,16,17]:
  c3.h(i)
c3.measure(18,18)
c3.barrier()
# 19
for i in [10,11,15,16,17]:
  c3.h(i)
c3.measure(19,19)
c3.barrier()
# 25
for i in [10,11,15,16,17,20,21,22,23,24]:
  c3.h(i)
c3.measure(25,25)
c3.barrier()
# 27
for i in [10,15,16,17,20,21,22,23,24,26]:
  c3.h(i)
c3.measure(27,27)
c3.barrier()
# 32
for i in [10,15,17,21,23,26,28,29,30,31]:
  c3.h(i)
c3.measure(32,32)
c3.barrier()
# 34
for i in [15,17,21,23,26,28,29,30,31,33]:
  c3.h(i)
c3.measure(34,34)
c3.barrier()
# 36
for i in [21,26,28,31,33,35]:
  c3.h(i)
c3.measure(36,36)
c3.barrier()
# 40
for i in [21,28,31,35,37,38,39]:
  c3.h(i)
c3.measure(40,40)
c3.barrier()
# 43
for i in [28,31,35,37,38,39,41,42]:
  c3.h(i)
c3.measure(43,43)
c3.barrier()
# 52
for i in [28,31,35,41,42,44,45,46,47,48,49,50,51]:
  c3.h(i)
c3.measure(52,52)
c3.barrier()
# 54
for i in [35,41,42,44,45,46,47,48,49,50,51,53]:
  c3.h(i)
c3.measure(54,54)
c3.barrier()
# 61
for i in [35,41,42,45,46,49,50,51,53,55,56,57,58,59,60]:
  c3.h(i)
c3.measure(61,61)
c3.barrier()
# 63
for i in [42,45,46,49,50,51,53,55,56,57,58,59,60,62]:
  c3.h(i)
c3.measure(63,63)
c3.barrier()
# another row
for i in [42,46,49,53,55,56,57,58,59,60,62]:
  c3.h(i)
c3.barrier()
# 12-44
for i in [12,13,20,22,24,29,30,33,37,38,39,44]:
  c3.measure(i,i)
  c3.barrier()
# 47
c3.h(46)
c3.measure(47,47)
c3.barrier()
# 48
c3.measure(48,48)
c3.barrier()
# 62
for i in [49,53,55,56,57,58,59,60]:
  c3.h(i)
c3.measure(62,62)
c3.barrier()
# 11-51
for i in [11,16,23,26,41,45,50,51]:
  c3.measure(i,i)
  c3.barrier()
# 56
c3.h(53)
c3.h(55)
c3.measure(56,56)
c3.barrier()
# 57
c3.h(55)
c3.measure(57,57)
c3.barrier()
# 59
c3.h(58)
c3.measure(59,59)
c3.barrier()
# more Hs
c3.h(58)
c3.h(60)
c3.barrier()
c3.h(60)
c3.barrier()
# 10-60
for i in [10,15,17,21,28,31,35,42,46,49,53,55,58,60]:
  c3.measure(i,i)
  c3.barrier()

c1.draw(output='mpl', filename='circ1_my.png', fold=100, plot_barriers=False, style="clifford")
c2.draw(output='mpl', filename='circ2_my.png', fold=100, plot_barriers=False, style="clifford")
c3.draw(output='mpl', filename='circ3_my.png', fold=100, plot_barriers=False, style="clifford")

backend = AerSimulator(method="stabilizer")
for circuit in [c1, c2, c3]:
  qc_compiled = transpile(circuit, backend)
  job_sim = backend.run(qc_compiled, shots=1024)
  result_sim = job_sim.result()
  counts = result_sim.get_counts(qc_compiled)
  print(counts.most_frequent())



