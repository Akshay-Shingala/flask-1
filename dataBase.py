class UserTable:
    def __init__(self, db, table):
        self.db = db
        self.table = table

    def getUser(self, email):
        return self.table.query.filter_by(email=email).first()

    def addUser(self, username, email, password, phone):
        newUser = self.table(
            username=username, email=email, password=password, phone=phone
        )
        self.db.session.add(newUser)
        self.db.session.commit()
