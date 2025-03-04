from fastapi import FastAPI
from pydantic import BaseModel
from enum import Enum

app= FastAPI()

# class Available_Cusine(str, Enum):
#     indian = "Indian"
#     si_lankan="Sri Lankan"
#     italian = "Italian"


# food_items = {'Indian':['Samosa','Thosa'],
#               'Sri Lankan':['Koththu','parata'],
#               'Italian':['Pizza','Browni']
#               }

# @app.get("/get_items/{cusine}")
# async def get_items(cusine:Available_Cusine):
#     return food_items.get(cusine)


# class Data(BaseModel):
#     name:str

# @app.post("/create/")
# async def create_data(data:Data):
#     return {"data": data}