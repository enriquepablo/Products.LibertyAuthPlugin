from setuptools import setup, find_packages
import os

version = '0.5-dev'

setup(name='Products.LibertyAuthPlugin',
      version=version,
      description="Liberty Alliance / SAML 2 Authentication Plugin for PAS",
      long_description=open("README.txt").read() + "\n" + open(os.path.join("docs", "HISTORY.txt")).read(),
      classifiers=["Framework :: Plone",
                   "Programming Language :: Python",],
      keywords='',
      author='Andreas Kaiser',
      author_email='disko@binary-punks.com',
      url='https://github.com/disko/Products.LibertyAuthPlugin',
      license='GPL',
      packages=find_packages(exclude=['ez_setup']),
      namespace_packages=['Products'],
      include_package_data=True,
      zip_safe=False,
      install_requires=[
          'setuptools',
          'Products.SOAPSupport',
          'SOAPpy',
      ],
      entry_points="""# -*- Entry points: -*-
                      [z3c.autoinclude.plugin]
                      target = plone""",
      )
