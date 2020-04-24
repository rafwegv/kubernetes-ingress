PROJECT_ROOT := $(shell git rev-parse --show-toplevel)
SITE_ROOT = ${PROJECT_ROOT}/site
BUILDDIR = ${SITE_ROOT}/docs-nginx-com/build
THEME_REPO = git@github.com:nginxinc/docs-nginx-com.git

.PHONY: all build clean setup

all: clean setup build

clean:
	rm -rf ${SITE_ROOT}

setup:
	mkdir -p ${SITE_ROOT}
	git clone -q --single-branch --branch master ${THEME_REPO} ${SITE_ROOT}/docs-nginx-com
	pip install -r ${SITE_ROOT}/docs-nginx-com/requirements.txt
	rsync -avOz ${PROJECT_ROOT}/docs-web/ ${SITE_ROOT}/docs-nginx-com/source/nginx-ingress-controller/ --exclude ${PROJECT_ROOT}/docs-web/Makefile

build:
	sphinx-build -b dirhtml -d ${BUILDDIR}/doctrees ${SITE_ROOT}/docs-nginx-com/source ${BUILDDIR}/dirhtml
	@echo "Build finished. The HTML pages are in ${BUILDDIR}/dirhtml."
