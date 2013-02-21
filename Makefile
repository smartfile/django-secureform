test:
	python tests.py

verify:
	pyflakes -x W django_secureform
	pep8 --exclude=migrations --ignore=E501,E225 django_secureform

install:
	python setup.py install

publish:
	python setup.py register
	python setup.py sdist upload
