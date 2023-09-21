import time
class PlayMaker:
    def __init__(self, time_limit):
        if time_limit < 0:
            time_limit = 0
        self.use = (time_limit != None)

        if self.use:
            self.toggle = False
            self.time_limit = time_limit * 60
            self.last_find_time = 0

            print(f"you playmaker is {self.time_limit}")

    
    def on(self):
       self.toggle = True
