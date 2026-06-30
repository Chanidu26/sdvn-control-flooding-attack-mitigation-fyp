import gurobipy as gp
from gurobipy import GRB
import csv
import time

try:
	time1 = time.time()*1000
	max = 40
	n = 4
	Bi = list()
	Ni = list()
	#f = 0.0
	#Li = list()
	Si = list()
	#Bim = list()
	Si_inner = list()

	with open("/root/ns-allinone-3.35/ns-3.35/scratch/optimization_data.csv",'r',encoding='UTF8') as csvfile:
		csvreader = csv.reader(csvfile,delimiter=',',quotechar='"',quoting=csv.QUOTE_MINIMAL)
		for row in csvreader:
			p = str(row)
			q = p.split(", ")
			r =0
			for sh in q:
				if (r==0):
					Si_inner = list()
					#Bim_inner = list()
					n = int(sh[2:-1])
				elif (r==1):
					Bi.append(int(sh[2:-1]))
				elif (r==2):
					Ni.append(int(sh[2:-1]))
					"""
					elif (r==3):
						f = float(sh[2:-1])
					elif (r==4):
						Li.append(int(sh[2:-1]))
					"""
				elif (r<(max+3)):
					if (int(sh[2:-1]) != 50000):
						Si_inner.append(int(sh[2:-1])-2)
					else:
						Si_inner.append(int(sh[2:-1]))
				elif (r<(3+2*max)):
					if (r==(max+3)):
						Si.append(Si_inner)
				"""
					Bim_inner.append(int(sh[2:-1]))
					if (r==3+2*max):
						Bim.append(Bim_inner)
				"""
				r = r + 1

	"""
	print('n is %g \n' % (n))
	print(*(Bi))
	print(*Ni)
	#print('f is %g \n' % (f))
	#print(*(Li))
	print(*(Si))
	#print(*(Bim))
	csvfile.close();
	"""
	ccn = 2
	cca = 1
	#cln = 10
	co = 1
	
	
	#chain
	"""
	n = 4
	#f = 1
	#Li = [84,84,84,84]
	Ni = [1, 2, 2, 1]
	Bi = [55, 55, 55, 55]
	"""
	"""	
	Bim = [[3, 50000, 50000, 50000, 50000],
               [3, 3, 50000, 50000, 50000],
               [3, 3, 50000, 50000, 50000],
               [3, 50000, 50000, 50000, 50000]]  
     	"""
	"""
	Si = [[1, 50000, 50000, 50000, 50000],
      	[0, 2, 50000, 50000, 50000],
              [1, 3, 50000, 50000, 50000],
              [2, 50000, 50000, 50000, 50000]]
	
	"""
        #tree
	"""
	n = 7
	#f = 1
	#Li = [84,84,84,84,84,84,84]
	Ni = [2, 3, 3, 1, 1, 1, 1]
	Bi = [55, 55, 55, 55, 55, 55, 55]
	"""
	"""
	
	Bim = [[3, 3, 50000, 50000, 50000],
               [3, 3, 3, 50000, 50000],
               [3, 3, 3, 50000, 50000],
               [3, 50000, 50000, 50000, 50000],
               [3, 50000, 50000, 50000, 50000],
               [3, 50000, 50000, 50000, 50000],
               [3, 50000, 50000, 50000, 50000]] 
	
	""" 
     	
	"""
	Si = [[1, 2, 50000, 50000, 50000],
      	[0, 3, 4, 50000, 50000],
              [0, 5, 6, 50000, 50000],
              [1, 50000, 50000, 50000, 50000],
              [1, 50000, 50000, 50000, 50000],
              [2, 50000, 50000, 50000, 50000],
              [2, 50000, 50000, 50000, 50000]]

        """    
	#Adhoc
	"""
	n = 7
	f = 1
	Li = [84,84,84,84,84,84,84]
	Ni = [1, 5, 3, 1, 2, 1, 1]
	Bi = [55, 2, 2, 55, 55, 55, 55]
	"""
	"""
	Bim = [[3, 50000, 50000, 50000, 50000],
               [3, 1, 3, 3, 3],
               [1, 3, 3, 50000, 50000],
               [3, 50000, 50000, 50000, 50000],
               [3, 3, 50000, 50000, 50000],
               [3, 50000, 50000, 50000, 50000],
               [3, 50000, 50000, 50000, 50000]]  
     	"""
	"""
	Si = [[1, 50000, 50000, 50000, 50000],
      	[0, 2, 4, 5, 6],
              [1, 4, 3, 50000, 50000],
              [2, 50000, 50000, 50000, 50000],
              [1, 2, 50000, 50000, 50000],
              [1, 50000, 50000, 50000, 50000],
              [1, 50000, 50000, 50000, 50000]]
	"""
	
	#Bim_mod = list()
	Si_mod = list()
	for i in range(n):
		set1 = set(Si[i][:])
		#set2 = set(Bim[i][:])
		if ((Si[i][-1]) ==50000):
			set1.remove(50000)
			#set2.remove(50000)
		Si_mod.append(list(set1))
		#Bim_mod.append(list(set2))
		
	
	m = gp.Model("data_collection")

	# Create decision variables
	x = m.addVars(n, vtype=GRB.BINARY, name="x")
	z = m.addVars(n, vtype=GRB.BINARY, name="z")


	# Set objective function
	"""
	obj_term1 = ccn*(gp.quicksum(z[i]*(gp.quicksum(Bim[i][m] for m in range(Ni[i]))) for i in range(n)))
	obj_term2 = cca*(gp.quicksum(Bi[i]*x[i] for i in range(n)))
	obj_term3 = cln*(gp.quicksum(Ni[i]*f*Li[i]*z[i] for i in range(n)))
	obj_term4 = co*(gp.quicksum(x[i]*(gp.quicksum(z[m] for m in Si_mod[i][:])) for i in range(n)))
	objective = (obj_term1) + (obj_term2) + (obj_term3) - (obj_term4)
	"""
	
	obj_term1 = ccn*(gp.quicksum(Ni[i]*z[i] for i in range(n)))
	obj_term2 = cca*(gp.quicksum(Bi[i]*x[i] for i in range(n)))
	obj_term3 = co*(gp.quicksum(x[i]*(gp.quicksum(z[m] for m in Si_mod[i][:])) for i in range(n)))
	objective = (obj_term1) + (obj_term2) - (obj_term3)
	m.setObjective(objective, gp.GRB.MINIMIZE)

	# Add constraints
	#print(s)
	for i in range(n):
		m.addConstr(x[i] + (gp.quicksum(x[m] for m in Si_mod[i][:])) >= 1)
		m.addConstr(x[i] + z[i] == 1)

	# Solve it!
	m.optimize()

	print(f"Optimal objective value: {m.objVal}")
	for j in range(n):
		print("Solution values: %s=%g, %s=%g" %(x[j].Varname, x[j].X, z[j].Varname, z[j].X))
	
	with open("/root/ns-allinone-3.35/ns-3.35/scratch/optimization_results.csv",'w',encoding='UTF8') as csvfile:
		writer = csv.writer(csvfile,delimiter=',',quotechar='"',quoting=csv.QUOTE_MINIMAL)
		for i in range(n):
			s1 = str(int(x[i].X))
			s2 = str(int(z[i].X))
			s3 = "begin, " + s1 +", " +s2 + ", " + "end"
			writer.writerow([s3])		
	csvfile.close();
	time2 = time.time()*1000
	delay = time2-time1
	print("delay is %d" %(delay))

except gp.GurobiError as e:
    print('Error code ' + str(e.errno) + ": " + str(e))

except AttributeError:
    print('Encountered an attribute error')
