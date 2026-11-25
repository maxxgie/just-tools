from setuptools import setup
setup(name="nmap-js", version="1.0.0", py_modules=["nmap","rawscan","probes","scripts","extras","advanced","pro"], entry_points={"console_scripts":["nmap=nmap:main"]})
