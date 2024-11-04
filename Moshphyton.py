# print("hello world")

# age = 20
# age = 30
# price = 19.95
# first_name = "Asqar"
# is_online = False 
# print(age)
# Name = input("What's your name ?")
# Age = input("what's your  age ?")
# Patient = input("Are you new  patient ?")

# print('New patient is' + Name , 'He is' + Age 'years old', "he  is a new patient")


# first= (input('enter first number '))
# second = (input('enter second number '))
# sum = float(first) +  float(second)

# print('Sum: '+ str(sum))

# course = "First time Phyton"
# # print(course.replace("n", "m")) #lower-upper-add-replace-find
# print("time" in course)

# changing string never  change the original string it returns  a new string.


# Arithmetic Operations
# print(10 // 3) #butun son
# print(10 / 3)
# print(10 % 3) #qoldiq
# print(10 ** 3) #10*10*10

# x=10
# x = x + 3
# x+=5
# x-=9
# print(x)


# Comparision operators
# x =3>=2
# x =3<=2
# x =3>2
# x =3<2
# x = 3==2 #equal
# x = 3!=2 #not equal
# x =3<2

# Logical operators
# price = 5
# print(price > 10 and price< 30) #True exactly
# print(price > 10 or price< 30) #at least one  True
# print(not price > 10 ) #Teskari

# IF Statements

# age = 19
# if age > 21:
#     print("enough Age to enter")
#     print("You don't need ID")
# elif age < 15:
#     print("not enough age to enter")
# else:
#     print("You need ID to enter")

weight = int(input("Weight: "))
choose = input("(K)g or (L)b: ")
if choose.upper() =="K":
    calc = weight / 0.45
    print("Your waight in Lb: " + str(calc))  # convert weight to pounds
else:
    calc = weight * 0.45
    print("Your waight in Kg: " + str(calc))  # convert weight to kilograms




