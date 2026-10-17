import setuptools

REQUIRES = ["bcrypt==4.1.2"]
REQUIRES = REQUIRES + ["passlib"]  # not a literal list: ignored

setuptools.setup(name="sub", install_requires=REQUIRES)
