import argparse
import datetime
import os
import socket
from urllib.parse import urljoin
from uuid import uuid4

import pytz
import requests
from datalake import GzippingFile


class UTC(object):
    # TODO factor this out into a proper library

    def __init__(self, d="now"):
        if d == "now":
            self._d = datetime.datetime.utcnow()
        elif isinstance(d, datetime.datetime):
            if not d.tzinfo:
                # naive, assume UTC
                d = d.replace(tzinfo=pytz.utc)
            elif d.tzinfo == pytz.utc:
                pass
            else:
                d = d.astimezone(pytz.utc)
            self._d = d
        else:
            # TODO convert strings, etc
            raise NotImplementedError()

    @property
    def iso(self):
        d = self._d.isoformat('T', 'microseconds')
        return d.replace("+00:00", "Z")


class MCAPI(object):

    def __init__(self, mc_base, jwt=None):
        self.mc_base = mc_base
        self.s = requests.session()
        self.jwt = None

    @classmethod
    def from_environ(cls, ignore_ssl=False):
        mc_api = cls(os.environ['MC_BASE'])
        if ignore_ssl:
            mc_api.s.verify = False
        if os.environ.get('MC_JWT'):
            mc_api.login(jwt=os.environ['MC_JWT'])
        else:
            mc_api.login(username=os.environ['MC_USERNAME'], password=os.environ['MC_PASSWORD'])
        return mc_api

    def get(self, path, *args, **kwargs):
        r = self.s.get(urljoin(self.mc_base, path), *args, **kwargs)
        r.raise_for_status()
        return r

    def getj(self, path, *args, **kwargs):
        r = self.get(path, *args, **kwargs)
        return r.json()

    def post(self, path, *args, **kwargs):
        r = self.s.post(urljoin(self.mc_base, path), *args, **kwargs)
        r.raise_for_status()
        return r

    def postj(self, path, *args, **kwargs):
        ret = self.s.post(urljoin(self.mc_base, path), *args, **kwargs)
        ret.raise_for_status()
        return ret.json()

    def put(self, path, *args, **kwargs):
        r = self.s.put(urljoin(self.mc_base, path), *args, **kwargs)
        r.raise_for_status()
        return r

    def putj(self, path, *args, **kwargs):
        r = self.s.put(urljoin(self.mc_base, path), *args, **kwargs)
        r.raise_for_status()
        return r.json()

    def patch(self, path, *args, **kwargs):
        r = self.s.patch(urljoin(self.mc_base, path), *args, **kwargs)
        r.raise_for_status()
        return r

    def patchj(self, path, *args, **kwargs):
        r = self.s.patch(urljoin(self.mc_base, path), *args, **kwargs)
        r.raise_for_status()
        return r.json()

    def delete(self, path, *args, **kwargs):
        r = self.s.delete(urljoin(self.mc_base, path), *args, **kwargs)
        r.raise_for_status()
        return r

    def get_passes(self, **kwargs):
        passes = self.getj("/api/v0/passes/", params=kwargs)
        return passes

    def get_pass(self, uuid, **kwargs):
        _pass = self.getj(f"/api/v0/passes/{uuid}/", params=kwargs)
        return _pass

    def get_accesses(self, **kwargs):
        accesses = self.getj("/api/v0/accesses/", params=kwargs)
        return accesses

    def put_pass(self, pass_id, **kwargs):
        """ requesting a pass signals intent that you'd like it to happen.
            If the pass already exists, then it will be marked is_desired
            If it does not exist, it will be created.
            A pass can be created from either an access_id, or a
              satellite, groundstation, start_time, and end_time.
            If you provide an access_id, you can override the start and end
              times by providing them as well.
        """
        return self.putj(
            f"/api/v0/passes/{pass_id}/",
            json=kwargs,
        )

    def delete_pass(self, pass_id, **kwargs):
        return self.delete(
            f"/api/v0/passes/{pass_id}/",
            json=kwargs,
        )

    def patch_pass(self, pass_id, **kwargs):
        return self.patchj(
            f"/api/v0/passes/{pass_id}/",
            json=kwargs,
        )

    def get_pass_track(self, pass_id, fmt='json'):
        if fmt == 'leaf':
            headers = {"accept": "application/vnd.leaf+text"}
            return self.get(
                "/api/v0/passes/{pass_id}/track/".format(pass_id=pass_id),
                headers=headers).text
        return self.getj(
            "/api/v0/passes/{pass_id}/track/".format(pass_id=pass_id))

    def patch_pass_attributes(self, pass_id, attributes):
        return self.patchj(
            f"/api/v0/passes/{pass_id}/attributes/",
            json=attributes,
        )

    def get_groundstations(self):
        return self.getj(
            "/api/v0/groundstations/"
        )

    def get_satellite(self, hwid):
        return self.getj(
            f"/api/v0/satellites/{hwid}/"
        )

    def get_satellites(self):
        return self.getj(
            "/api/v0/satellites/"
        )

    def patch_satellite(self, hwid, **kwargs):
        return self.patchj(
            f"/api/v0/satellites/{hwid}/",
            json=kwargs
        )

    def get_task_stacks(self, **kwargs):
        return self.getj(
            '/api/v0/task-stacks/',
            params=kwargs,
        )

    def get_task_stack(self, uuid, **kwargs):
        return self.getj(
            f'/api/v0/task-stacks/{uuid}/',
            params=kwargs
        )

    def put_task_stack(self, uuid, **kwargs):
        return self.putj(
            f'/api/v0/task-stacks/{uuid}/',
            json=kwargs,
        )

    def get_pass_task_stack(self, uuid, **kwargs):
        return self.getj(
            f'/api/v0/passes/{uuid}/task-stack/',
            json=kwargs
        )

    def get_latest_file(self, what, where, **kwargs):
        return self.getj(
            f'/api/v0/files/latest/{what}/{where}/',
            params=kwargs
        )

    def get_files(self, what, **kwargs):
        kwargs.update({"what": what})
        return self.getj(
            f'/api/v0/files/search/',
            params=kwargs
        )

    def get_files_by_cid(self, cid, **kwargs):
        return self.getj(
            f'/api/v0/files/cid/{cid}/',
            params=kwargs
        )

    def get_files_by_work_id(self, work_id, **kwargs):
        return self.getj(
            f'/api/v0/files/work-id/{work_id}/',
            params=kwargs
        )

    def get_file(self, uuid):
        return self.getj(
            f'/api/v0/files/{uuid}/'
        )

    def download_file(self, uuid):
        return self.get(
            f'/api/v0/files/{uuid}/data/'
        )

    def download_cid(self, cid):
        return self.get(
            f'/api/v0/raw-file/{cid}/data/'
        )

    def upload_file(self, path, what, uuid=None, where=None, start=None,
                    end=None, work_id=None, content_type=None):

        if uuid is None:
            uuid = str(uuid4())

        if start is None:
            start = UTC("now").iso
        else:
            start = UTC(start).iso

        if where is None:
            where = socket.getfqdn()

        f = GzippingFile.from_filename(
            path,
            what=what,
            where=where,
            start=start,
            work_id=work_id
        )

        # get signed upload
        signed = self.postj(
            f'/api/v0/files/presign/',
            json=f.metadata
        )

        file_tuple = ("file", f)
        if content_type is not None:
            file_tuple += (content_type,)

        # upload file
        if "url" in signed:
            signed["fields"]["Content-Encoding"] = "gzip"
            resp = requests.post(
                signed["url"],
                data=signed["fields"],
                files=[file_tuple]
            )
            resp.raise_for_status()

        # upload metadata
        return self.putj(
            f'/api/v0/files/{uuid}/',
            json=f.metadata
        )

    def login(self, username=None, password=None, jwt=None):
        if username is not None and jwt is not None:
            raise ValueError("Can't give both a username and a jwt")
        if username is not None:
            self.s.auth = (username, password)
            self.jwt = self.get('/api/v0/auth/jwt').text
            self.s.auth = None
        else:
            self.jwt = jwt

        self.s.headers.update({'Authorization': f'Bearer {self.jwt}'})
        # TODO save token to disk?

def add_parser_defaults(parser):
    parser.add_argument(
        "--mc-base",
        dest="mc_api",
        required="MC_BASE" not in os.environ,
        type=MCAPI,
        default=MCAPI(os.environ.get("MC_BASE")))

    add_login_to_parser(parser)
    add_ssl_to_parser(parser)

def add_login_to_parser(parser):
    auth = parser.add_mutually_exclusive_group(required=(
        not os.environ.get("MC_USERNAME") and not os.environ.get("MC_JWT")
    ))
    auth.add_argument(
        "--username",
        "-u",
        dest="username",
        default=os.environ.get("MC_USERNAME"),
    )
    parser.add_argument(
        "--password",
        "-p",
        dest="password",
        default=os.environ.get("MC_PASSWORD"),
    )
    auth.add_argument(
        "--jwt",
        "-j",
        dest="jwt",
        default=os.environ.get("MC_JWT"),
    )

def add_ssl_to_parser(parser):
    parser.add_argument(
        '--ignore-ssl',
        action='store_true',
        default=False)

def get_parser():
    parser = argparse.ArgumentParser()
    add_parser_defaults(parser)
    return parser

def handle_default_args(args):
    if args.ignore_ssl:
        args.mc_api.s.verify = False

    if args.jwt:
        args.mc_api.login(jwt=args.jwt)
    else:
        args.mc_api.login(username=args.username, password=args.password)

def from_environ(ignore_ssl=False):
    # deprecated, use MCAPI.from_environ()
    mc_api = MCAPI(os.environ['MC_BASE'])
    if ignore_ssl:
        mc_api.s.verify = False
    if os.environ.get('MC_JWT'):
        mc_api.login(jwt=os.environ['MC_JWT'])
    else:
        mc_api.login(username=os.environ['MC_USERNAME'], password=os.environ['MC_PASSWORD'])

    return mc_api
