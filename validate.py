def checkString(string):
    import re

    pattern = r"^[A-Za-z ]+$"
    if re.match(pattern, string):
        return True
    return False


def checkNumber(number):
    import re

    pattern = r"^[0-9]{10}+$"
    if re.match(pattern, number):
        return True
    return False


def checkEmail(email):
    import re

    pattern = r"^[\w\.-]+@[\w\.-]+\.[\w]+$"
    if re.match(pattern, email):
        return True
    return False
