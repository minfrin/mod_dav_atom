/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


/*
 * The Apache mod_dav_atom module exposes collections and resources in a
 * WebDAV server as an Atom feed.
 *
 *  Author: Graham Leggett
 *
 * If a GET is made on a collection, and the requested content type is
 * application/atom+xml, an atom:feed is generated containing a single
 * entry for each resource in the collection.
 *
 * The elements of the Atom feed are read from the WebDAV properties of the
 * resources. Further modules can be used to inspect resources to generate
 * live properties.
 *
 * The Atom feed is an XML document, and can thus be filtered with an optional
 * XSLT transform.
 *
 * Basic configuration:
 *
 * <Location />
 *   Dav on
 *   DavAtom on
 *
 *   # if properties cannot be found in webdav, generate them as follows:
 *   DavAtomStylesheet atom.xsl
 *   DavAtomFeedId https://www.example.com%{REQUEST_URI}
 *   DavAtomFeedLink https://www.example.com%{REQUEST_URI}
 *   DavAtomEntryId https://www.example.com%{REQUEST_URI}
 *
 * </Location>
 *
 */
#include <apr_lib.h>
#include <apr_escape.h>
#include <apr_strings.h>
#include "apr_sha1.h"
#include "apr_encode.h"
#include "apr_tables.h"
#include "apr_date.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_script.h"

#include "mod_dav.h"

#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#include "config.h"

module AP_MODULE_DECLARE_DATA dav_atom_module;

#define DAV_ATOM_HANDLER "httpd/dav-atom"

#define DAV_XML_NAMESPACE "DAV:"
#define DAV_ATOM_XML_NAMESPACE "http://www.w3.org/2005/Atom"

#define DAV_ATOM_CONTENT_TYPE "application/atom+xml"

typedef struct
{
    int dav_atom_set :1;
    int stylesheet_set :1;
    int feed_id_set :1;
    int feed_link_set :1;
    int entry_id_set :1;
    int entry_link_set :1;
    int dav_atom;
    ap_expr_info_t *stylesheet;
    ap_expr_info_t *feed_id;
    ap_expr_info_t *feed_link;
    ap_expr_info_t *entry_id;
    ap_expr_info_t *entry_link;
} dav_atom_config_rec;

typedef struct dav_atom_ctx {
    dav_walk_params w;
    request_rec *r;
    apr_bucket_brigade *bb;
    dav_error *err;
    apr_xml_elem *feed;
    apr_pool_t *scratchpool;
    int count;
    int ns;
} dav_atom_ctx;

static void *create_dav_atom_dir_config(apr_pool_t *p, char *d)
{
    dav_atom_config_rec *conf = apr_pcalloc(p, sizeof(dav_atom_config_rec));

    return conf;
}

static void *merge_dav_atom_dir_config(apr_pool_t *p, void *basev, void *addv)
{
    dav_atom_config_rec *new = (dav_atom_config_rec *) apr_pcalloc(p,
            sizeof(dav_atom_config_rec));
    dav_atom_config_rec *add = (dav_atom_config_rec *) addv;
    dav_atom_config_rec *base = (dav_atom_config_rec *) basev;

    new->dav_atom = (add->dav_atom_set == 0) ? base->dav_atom : add->dav_atom;
    new->dav_atom_set = add->dav_atom_set || base->dav_atom_set;

    new->stylesheet = (add->stylesheet_set == 0) ? base->stylesheet : add->stylesheet;
    new->stylesheet_set = add->stylesheet_set || base->stylesheet_set;

    new->feed_id = (add->feed_id_set == 0) ? base->feed_id : add->feed_id;
    new->feed_id_set = add->feed_id_set || base->feed_id_set;

    new->feed_link = (add->feed_link_set == 0) ? base->feed_link : add->feed_link;
    new->feed_link_set = add->feed_link_set || base->feed_link_set;

    new->entry_id = (add->entry_id_set == 0) ? base->entry_id : add->entry_id;
    new->entry_id_set = add->entry_id_set || base->entry_id_set;

    new->entry_link = (add->entry_link_set == 0) ? base->entry_link : add->entry_link;
    new->entry_link_set = add->entry_link_set || base->entry_link_set;

    return new;
}

static const char *set_dav_atom(cmd_parms *cmd, void *dconf, int flag)
{
    dav_atom_config_rec *conf = dconf;

    conf->dav_atom = flag;
    conf->dav_atom_set = 1;

    return NULL;
}

static const char *set_dav_atom_stylesheet(cmd_parms *cmd, void *dconf, const char *stylesheet)
{
    dav_atom_config_rec *conf = dconf;
    const char *expr_err = NULL;

    conf->stylesheet = ap_expr_parse_cmd(cmd, stylesheet, AP_EXPR_FLAG_STRING_RESULT,
            &expr_err, NULL);

    if (expr_err) {
        return apr_pstrcat(cmd->temp_pool,
                "Cannot parse expression '", stylesheet, "': ",
                expr_err, NULL);
    }

    conf->stylesheet_set = 1;

    return NULL;
}

static const char *set_dav_atom_feed_id(cmd_parms *cmd, void *dconf, const char *id)
{
    dav_atom_config_rec *conf = dconf;
    const char *expr_err = NULL;

    conf->feed_id = ap_expr_parse_cmd(cmd, id, AP_EXPR_FLAG_STRING_RESULT,
            &expr_err, NULL);

    if (expr_err) {
        return apr_pstrcat(cmd->temp_pool,
                "Cannot parse expression '", id, "': ",
                expr_err, NULL);
    }

    conf->feed_id_set = 1;

    return NULL;
}

static const char *set_dav_atom_feed_link(cmd_parms *cmd, void *dconf, const char *link)
{
    dav_atom_config_rec *conf = dconf;
    const char *expr_err = NULL;

    conf->feed_link = ap_expr_parse_cmd(cmd, link, AP_EXPR_FLAG_STRING_RESULT,
            &expr_err, NULL);

    if (expr_err) {
        return apr_pstrcat(cmd->temp_pool,
                "Cannot parse expression '", link, "': ",
                expr_err, NULL);
    }

    conf->feed_link_set = 1;

    return NULL;
}

static const char *set_dav_atom_entry_id(cmd_parms *cmd, void *dconf, const char *id)
{
    dav_atom_config_rec *conf = dconf;
    const char *expr_err = NULL;

    conf->entry_id = ap_expr_parse_cmd(cmd, id, AP_EXPR_FLAG_STRING_RESULT,
            &expr_err, NULL);

    if (expr_err) {
        return apr_pstrcat(cmd->temp_pool,
                "Cannot parse expression '", id, "': ",
                expr_err, NULL);
    }

    conf->entry_id_set = 1;

    return NULL;
}

static const char *set_dav_atom_entry_link(cmd_parms *cmd, void *dconf, const char *link)
{
    dav_atom_config_rec *conf = dconf;
    const char *expr_err = NULL;

    conf->entry_link = ap_expr_parse_cmd(cmd, link, AP_EXPR_FLAG_STRING_RESULT,
            &expr_err, NULL);

    if (expr_err) {
        return apr_pstrcat(cmd->temp_pool,
                "Cannot parse expression '", link, "': ",
                expr_err, NULL);
    }

    conf->entry_link_set = 1;

    return NULL;
}

static const command_rec dav_atom_cmds[] =
{
    AP_INIT_FLAG("DavAtom",
        set_dav_atom, NULL, RSRC_CONF | ACCESS_CONF,
        "When enabled, the URL space will return Atom feeds."),
    AP_INIT_TAKE1("DavAtomStylesheet", set_dav_atom_stylesheet, NULL, RSRC_CONF | ACCESS_CONF,
        "Set the XSLT stylesheet to be used when rendering the output."),
    AP_INIT_TAKE1("DavAtomFeedId", set_dav_atom_feed_id, NULL, ACCESS_CONF,
        "Set the ID of the feed to a given value. Overridden by ID in atom:feed WebDAV property."),
    AP_INIT_TAKE1("DavAtomFeedLink", set_dav_atom_feed_link, NULL, ACCESS_CONF,
        "Set the link of the feed to a given value. Overridden by link in atom:feed WebDAV property."),
    AP_INIT_TAKE1("DavAtomEntryId", set_dav_atom_entry_id, NULL, ACCESS_CONF,
        "Set the ID of the entry to a given value. Overridden by ID in atom:entry WebDAV property."),
    AP_INIT_TAKE1("DavAtomEntryLink", set_dav_atom_entry_link, NULL, ACCESS_CONF,
        "Set the link of the entry to a given value. Overridden by link in atom:entry WebDAV property."),
    { NULL }
};

/*
 * dav_log_err()
 *
 * Write error information to the log.
 */
static void dav_log_err(request_rec *r, dav_error *err, int level)
{
    dav_error *errscan;

    /* Log the errors */
    /* ### should have a directive to log the first or all */
    for (errscan = err; errscan != NULL; errscan = errscan->prev) {
        if (errscan->desc == NULL)
            continue;

        /* Intentional no APLOGNO */
        ap_log_rerror(APLOG_MARK, level, errscan->aprerr, r, "%s  [%d, #%d]",
                      errscan->desc, errscan->status, errscan->error_id);
    }
}

/* find and remove the (unique) child with a tagname in the given namespace */
static void dav_remove_child_ns(const apr_xml_elem *elem,
                                int ns, const char *tagname)
{
    apr_xml_elem *child = elem->first_child;
    apr_xml_elem *last = NULL;

    for (; child; child = child->next) {
        if (child->ns == ns && !strcmp(child->name, tagname)) {
            if (child->parent->first_child == child) {
                child->parent->first_child = child->next;
            }
            if (last) {
                last->next = child->next;
            }
            if (child->parent->last_child == child) {
                child->parent->last_child = last;
            }
        }
        else {
            last = child;
        }
    }
    return;
}

static apr_xml_elem *dav_add_child_ns(apr_pool_t *p, apr_xml_elem *elem,
                                      int ns, const char *tagname,
                                         const char *first_cdata,
                                      const char *following_cdata)
{
    apr_xml_elem *child;

    /* add the id element */
    child = apr_pcalloc(p, sizeof(apr_xml_elem));
    child->name = tagname;
    child->ns = ns;

    if (first_cdata) {
        apr_text_append(p, &child->first_cdata, first_cdata);
    }
    if (following_cdata) {
        apr_text_append(p, &child->following_cdata, following_cdata);
    }

    child->next = elem->first_child;
    elem->first_child = child;
    if (!elem->last_child) {
        elem->last_child = child;
    }

    return child;
}

static apr_xml_attr *dav_add_attr_ns(apr_pool_t *p, apr_xml_elem *elem,
                                     int ns, const char *tagname,
                                     const char *value)
{
    apr_xml_attr *attr;

    /* add the id element */
    attr = apr_pcalloc(p, sizeof(apr_xml_attr));
    attr->name = tagname;
    attr->ns = ns;

    attr->value = value;

    attr->next = elem->attr;
    elem->attr = attr;

    return attr;
}

static int dav_atom_type_checker(request_rec *r)
{
    /*
     * Short circuit other modules that want to overwrite the content type
     * as soon as they detect a directory.
     */
    if (r->content_type && !strcmp(r->content_type, DAV_ATOM_HANDLER)) {
        return OK;
    }

    return DECLINED;
}

/* Factorized helper function: prep request_rec R for a atom
   response and write <atom:feed> tag into BB, destined for
   R->output_filters.  Use xml NAMESPACES in initial tag, if
   non-NULL. */
static void dav_begin_atom_feed(dav_atom_ctx *ctx,
                                request_rec *r, int status,
                                const apr_xml_elem *feed,
                                apr_array_header_t *namespaces)
{
    dav_atom_config_rec *conf = ap_get_module_config(r->per_dir_config,
            &dav_atom_module);

    apr_bucket_brigade *bb = ctx->bb;

    /* pass this way just once */
    if (ctx->count) {
        return;
    }

    /* Set the correct status and Content-Type */
    r->status = status;
    ap_set_content_type(r, DAV_ATOM_CONTENT_TYPE);

    /* send the stylesheet */
    ap_fputs(r->output_filters, bb, DAV_XML_HEADER DEBUG_CR);

    if (conf->stylesheet) {
        const char *err = NULL, *stylesheet;

        stylesheet = ap_expr_str_exec(r, conf->stylesheet, &err);
        if (err) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                            "Failure while evaluating the stylesheet URL expression for '%s', "
                            "stylesheet ignored: %s", r->uri, err);
        }
        else {
            ap_fputs(r->output_filters, bb, "<?xml-stylesheet type=\"text/xsl\" href=\"");
            ap_fputs(r->output_filters, bb, ap_escape_html(r->pool, stylesheet));
            ap_fputs(r->output_filters, bb, "\"?>" DEBUG_CR);
        }

    }

    if (!namespaces) {
        namespaces = apr_array_make(ctx->scratchpool, 1, sizeof(const char *));
    }
    ctx->ns = apr_xml_insert_uri(namespaces, DAV_ATOM_XML_NAMESPACE);

    /* Send the headers and atom feed response now... */
    ap_fprintf(r->output_filters, bb, "<ns%d:feed", ctx->ns);

    if (namespaces != NULL) {
       int i;

       for (i = namespaces->nelts; i--; ) {
           ap_fprintf(r->output_filters, bb, " xmlns:ns%d=\"%s\"", i,
                      APR_XML_GET_URI_ITEM(namespaces, i));
       }
    }

    ap_fputs(r->output_filters, bb, ">" DEBUG_CR);

    if (feed) {
        const char *target;
        apr_size_t tsize;

        const apr_xml_elem *elem = feed;

        for (elem = elem->first_child; elem; elem = elem->next) {
            apr_xml_to_text(ctx->scratchpool, elem, APR_XML_X2T_FULL, NULL, NULL,
                    &target, &tsize);

            ap_fwrite(r->output_filters, bb, target, tsize - 1);
            ap_fputs(r->output_filters, bb, DEBUG_CR);
        }

    }

}

/* Finish a multistatus response started by dav_begin_atom_feed: */
static apr_status_t dav_finish_atom_feed(dav_atom_ctx *ctx, request_rec *r)
{
    apr_bucket_brigade *bb = ctx->bb;
    apr_bucket *b;

    ap_fprintf(r->output_filters, bb, "</ns%d:feed>" DEBUG_CR, ctx->ns);

    /* indicate the end of the response body */
    b = apr_bucket_eos_create(r->connection->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);

    /* deliver whatever might be remaining in the brigade */
    return ap_pass_brigade(r->output_filters, bb);
}

static void dav_send_atom_entry(dav_atom_ctx *ctx,
                                request_rec *r,
                                const apr_xml_elem *entry,
                                apr_array_header_t *namespaces)
{

    apr_bucket_brigade *bb = ctx->bb;

    if (!entry) {
        return;
    }

    /* Send the headers and atom feed response now... */
    ap_fprintf(r->output_filters, bb, "<ns%d:entry", ctx->ns);

    if (namespaces != NULL) {
       int i;

       for (i = namespaces->nelts; i--; ) {
           ap_fprintf(r->output_filters, bb, " xmlns:ns%d=\"%s\"", i,
                      APR_XML_GET_URI_ITEM(namespaces, i));
       }
    }

    ap_fputs(r->output_filters, bb, ">" DEBUG_CR);

    if (entry) {
        const char *target;
        apr_size_t tsize;

        apr_xml_to_text(ctx->scratchpool, entry, APR_XML_X2T_INNER, NULL, NULL,
                &target, &tsize);

        ap_fwrite(r->output_filters, bb, target, tsize - 1);
        ap_fputs(r->output_filters, bb, DEBUG_CR);

    }

    ap_fprintf(r->output_filters, bb, "</ns%d:entry>" DEBUG_CR, ctx->ns);

}

static dav_error *dav_atom_get_parsed_props(apr_pool_t *p,
        request_rec *r, dav_get_props_result *result, apr_xml_doc **pdoc)
{
    apr_xml_parser *parser;
    const char *buf;
    apr_text *t;
    apr_status_t status;

    /* parse the result above */
    parser = apr_xml_parser_create(p);

    /* create the response element with namespaces */
    buf = "<D:response xmlns:D=\"DAV:\"";
    status = apr_xml_parser_feed(parser, buf, strlen(buf));

    for (t = result->xmlns; t && !status; t = t->next) {
        status = apr_xml_parser_feed(parser, t->text, strlen(t->text));
    }

    if (!status) {
        buf = ">";
        status = apr_xml_parser_feed(parser, buf, strlen(buf));
    }

    /* parse the property itself */
    for (t = result->propstats; t && !status; t = t->next) {
        status = apr_xml_parser_feed(parser, t->text, strlen(t->text));
    }

    /* close the tag */
    if (!status) {
        buf = "</D:response>";
        status = apr_xml_parser_feed(parser, buf, strlen(buf));
    }

    if (!status) {
        status = apr_xml_parser_done(parser, pdoc);
    }

    if (status) {
        char errbuf[200];

        (void) apr_xml_parser_geterror(parser, errbuf, sizeof(errbuf));

        return dav_new_error(r->pool, HTTP_INTERNAL_SERVER_ERROR, 0,
                status,
                apr_psprintf(r->pool, "Could not XML parse properties: %s",
                        errbuf));
    }

    return NULL;
}

static dav_error * dav_atom_get_walker(dav_walk_resource *wres, int calltype)
{
    dav_atom_ctx *ctx = wres->walk_ctx;
    dav_error *err = NULL;
    dav_propdb *propdb;
    request_rec *rr;
    apr_xml_doc *propfind;
    apr_xml_doc *response;
    apr_xml_parser *parser;
    const char *buf;

    const char *feed_id = NULL, *entry_id = NULL, *feed_link = NULL, *entry_link = NULL;

    /* skip any resource whose name starts with a dot */
    if (strstr(wres->resource->uri, "/.")) {
        apr_pool_clear(ctx->scratchpool);
        return NULL;
    }

    /* check for any method preconditions */
    if (dav_run_method_precondition(ctx->r, NULL, wres->resource, NULL, &err) != DECLINED
            && err) {
        apr_pool_clear(ctx->scratchpool);
        return NULL;
    }

    /* first collection resource? */
    if (ctx->count == 0) {

        dav_atom_config_rec *conf = ap_get_module_config(ctx->r->per_dir_config,
                &dav_atom_module);

        if (conf->feed_id) {
            const char *err = NULL;

            feed_id = apr_pstrdup(ctx->scratchpool, ap_expr_str_exec(ctx->r, conf->feed_id, &err));
            if (err) {
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, ctx->r,
                                "Failure while evaluating the feed ID expression for '%s', "
                                "feed ID ignored: %s", ctx->r->uri, err);
            }

        }
        else {
            feed_id = apr_pstrcat(ctx->scratchpool, "https://",
                    ctx->r->server->server_hostname ?
                            ctx->r->server->server_hostname : "", ctx->r->uri, NULL);
        }

        if (conf->feed_link) {
            const char *err = NULL;

            feed_link = apr_pstrdup(ctx->scratchpool, ap_expr_str_exec(ctx->r, conf->feed_link, &err));
            if (err) {
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, ctx->r,
                                "Failure while evaluating the feed link expression for '%s', "
                                "feed link ignored: %s", ctx->r->uri, err);
            }

        }
        else {
            feed_link = apr_pstrcat(ctx->scratchpool, "https://",
                    ctx->r->server->server_hostname ?
                            ctx->r->server->server_hostname : "", ctx->r->uri, NULL);
        }

    }
    else {

        /* are we allowed to walk this resource? */
        rr = ap_sub_req_method_uri(ctx->r->method, wres->resource->uri, ctx->r, NULL);
        if (rr->status != HTTP_OK) {
            err = dav_new_error(rr->pool, rr->status, 0, 0,
                                apr_psprintf(rr->pool,
                                "DAV subrequest not allowed for %s",
                                ap_escape_html(rr->pool, rr->uri)));
            dav_log_err(rr, err, APLOG_DEBUG);
            ap_destroy_sub_req(rr);
            apr_pool_clear(ctx->scratchpool);
            return NULL;
        }
        else {

            dav_atom_config_rec *conf = ap_get_module_config(rr->per_dir_config,
                    &dav_atom_module);

            if (conf->entry_id) {
                const char *err = NULL;

                entry_id = apr_pstrdup(ctx->scratchpool,
                        ap_expr_str_exec(rr, conf->entry_id, &err));
                if (err) {
                    ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, rr,
                                    "Failure while evaluating the entry ID expression for '%s', "
                                    "feed ID ignored: %s", rr->uri, err);
                }

            }
            else {
                entry_id = apr_pstrcat(ctx->scratchpool, "https://",
                        rr->server->server_hostname ? rr->server->server_hostname : "", rr->uri, NULL);
            }

            if (conf->entry_link) {
                const char *err = NULL;

                entry_link = apr_pstrdup(ctx->scratchpool,
                        ap_expr_str_exec(rr, conf->entry_link, &err));
                if (err) {
                    ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, rr,
                                    "Failure while evaluating the entry link expression for '%s', "
                                    "entry ID ignored: %s", rr->uri, err);
                }

            }
            else {
                entry_link = apr_pstrcat(ctx->scratchpool, "https://",
                        rr->server->server_hostname ? rr->server->server_hostname : "", rr->uri, NULL);
            }

        }
        ap_destroy_sub_req(rr);
    }

    /* parse the propfind request */
    parser = apr_xml_parser_create(ctx->scratchpool);

    buf = "<D:propfind xmlns:D=\"DAV:\">"
            "<D:prop>"
              "<A:feed xmlns:A=\"" DAV_ATOM_XML_NAMESPACE "\"/>"
              "<A:entry xmlns:A=\"" DAV_ATOM_XML_NAMESPACE "\"/>"
              "<D:displayname/>"
              "<D:getcontenttype/>"
              "<D:getcontentlength/>"
              "<D:getlastmodified/>"
            "</D:prop>"
          "</D:propfind>";

    apr_xml_parser_feed(parser, buf, strlen(buf));
    apr_xml_parser_done(parser, &propfind);

    /*
    ** Note: ctx->doc can only be NULL for DAV_PROPFIND_IS_ALLPROP. Since
    ** dav_get_allprops() does not need to do namespace translation,
    ** we're okay.
    **
    ** Note: we cast to lose the "const". The propdb won't try to change
    ** the resource, however, since we are opening readonly.
    */
    err = dav_popen_propdb(ctx->scratchpool,
                           ctx->r, ctx->w.lockdb, wres->resource, 1,
                           propfind->namespaces, &propdb);

    if (propdb) {
        apr_xml_elem *propstat, *prop, *feed, *entry, *title, *updated, *displayname,
            *lastmodified, *link, *id, *contenttype, *contentlength;
        dav_get_props_result result = { 0 };

        result = dav_get_props(propdb, propfind);

        err = dav_atom_get_parsed_props(ctx->scratchpool, ctx->r, &result, &response);

        if (!err) {

            ctx->ns = apr_xml_insert_uri(response->namespaces, DAV_ATOM_XML_NAMESPACE);

            propstat = dav_find_child(response->root, "propstat");
            if (!propstat) {
                err = dav_new_error(ctx->r->pool, HTTP_INTERNAL_SERVER_ERROR, 0, 0,
                        "The 'propstat' element was expected, but was missing.");
            }
        }

        if (!err) {
            prop = dav_find_child(propstat, "prop");
            if (!prop) {
                err = dav_new_error(ctx->r->pool, HTTP_INTERNAL_SERVER_ERROR, 0, 0,
                        "The 'prop' element was expected, but was missing.");
            }
        }

        if (!err) {

            displayname = dav_find_child(prop, "displayname");
            contentlength = dav_find_child(prop, "getcontentlength");
            contenttype = dav_find_child(prop, "getcontenttype");
            lastmodified = dav_find_child(prop, "getlastmodified");

            /*
             * Is this the first resource?
             *
             * If so, this will be the enclosing collection, and the
             * feed will not yet have been emitted.
             *
             * Send all the children of the atom:feed element.
             */
            if (ctx->count == 0) {

                feed = dav_find_child_ns(prop, ctx->ns, "feed");
                if (!feed) {
                    feed = dav_add_child_ns(ctx->scratchpool, prop, ctx->ns, "feed", NULL,
                            NULL);
                }

                id = dav_find_child_ns(feed, ctx->ns, "id");
                if (!id) {

                    /* set the ID of the feed */
                    if (feed_id) {
                        dav_remove_child_ns(feed, ctx->ns, "id");

                        /* add the id element */
                        dav_add_child_ns(ctx->scratchpool, feed, ctx->ns, "id", feed_id,
                                NULL);
                    }
                    else {
                        err = dav_new_error(ctx->r->pool, HTTP_INTERNAL_SERVER_ERROR, 0, 0,
                                "No 'id' element in atom:feed, this feed is invalid.");
                    }
                }

                /* make sure we have a atom:title */
                title = dav_find_child_ns(feed, ctx->ns, "title");
                if (!title) {

                    /* set the title to the displayname, failing that the uri */
                    if (displayname) {
                        dav_add_child_ns(ctx->scratchpool, feed, ctx->ns, "title",
                                displayname->first_cdata.first->text, NULL);
                    }
                    else {
                        dav_add_child_ns(ctx->scratchpool, feed, ctx->ns, "title",
                                wres->resource->uri, NULL);
                    }

                }

                /* make sure we have a atom:updated */
                updated = dav_find_child_ns(feed, ctx->ns, "updated");
                if (!updated && lastmodified->first_cdata.first->text) {

                    apr_time_t lm = apr_date_parse_http(
                            lastmodified->first_cdata.first->text);

                    apr_time_exp_t texp;
                    char ts[128];
                    apr_size_t len;

                    apr_time_exp_gmt(&texp, lm);
                    apr_strftime(ts, &len, sizeof(ts)-1, "%Y-%m-%dT%H:%M:%SZ", &texp);
                    ts[len] = '\0';

                    dav_add_child_ns(ctx->scratchpool, feed, ctx->ns, "updated",
                            apr_pstrdup(ctx->scratchpool, ts), NULL);

                }

                /* make sure we have a atom:link */
                link = dav_find_child_ns(feed, ctx->ns, "link");
                if (!link) {
                    link = dav_add_child_ns(ctx->scratchpool, feed, ctx->ns, "link",
                            NULL, NULL);

                    dav_add_attr_ns(ctx->scratchpool, link, ctx->ns, "rel",
                            "self");
                    dav_add_attr_ns(ctx->scratchpool, link, ctx->ns, "href",
                            feed_link);
                }

                if (!err) {
                    dav_begin_atom_feed(ctx, ctx->r, HTTP_OK, feed,
                            response->namespaces);

                    ctx->count++;
                }
            }

            /*
             * Is this a subsequent resource?
             *
             * If so, these will be the entries.
             */
            else {

                entry = dav_find_child_ns(prop, ctx->ns, "entry");
                if (!entry) {
                    entry = dav_add_child_ns(ctx->scratchpool, prop, ctx->ns, "entry", NULL,
                            NULL);
                }

                if (entry_id) {
                    dav_remove_child_ns(entry, ctx->ns, "id");

                    /* add the id element */
                    dav_add_child_ns(ctx->scratchpool, entry, ctx->ns, "id", entry_id,
                            NULL);
                }
                else {
                    err = dav_new_error(ctx->r->pool, HTTP_INTERNAL_SERVER_ERROR, 0, 0,
                            "No 'id' element in atom:entry, this feed is invalid.");
                }

                /* make sure we have a atom:title */
                title = dav_find_child_ns(entry, ctx->ns, "title");
                if (!title) {

                    /* set the title to the displayname, failing that the uri */
                    if (displayname) {
                        dav_add_child_ns(ctx->scratchpool, entry, ctx->ns, "title",
                                displayname->first_cdata.first->text, NULL);
                    }
                    else {
                        dav_add_child_ns(ctx->scratchpool, entry, ctx->ns, "title",
                                wres->resource->uri, NULL);
                    }

                }

                /* make sure we have a atom:updated */
                updated = dav_find_child_ns(entry, ctx->ns, "updated");
                if (!updated) {

                    apr_time_t lm = apr_date_parse_http(
                            lastmodified->first_cdata.first->text);

                    apr_time_exp_t texp;
                    char ts[128];
                    apr_size_t len;

                    apr_time_exp_gmt(&texp, lm);
                    apr_strftime(ts, &len, sizeof(ts)-1, "%Y-%m-%dT%H:%M:%SZ", &texp);
                    ts[len] = '\0';

                    dav_add_child_ns(ctx->scratchpool, entry, ctx->ns, "updated",
                            apr_pstrdup(ctx->scratchpool, ts), NULL);

                }

                /* make sure we have a atom:link */
                link = dav_find_child_ns(entry, ctx->ns, "link");
                if (!link) {
                    link = dav_add_child_ns(ctx->scratchpool, entry, ctx->ns, "link",
                            NULL, NULL);

                    if (contenttype && contenttype->first_cdata.first->text
                    		&& !strncmp(contenttype->first_cdata.first->text, "text/",
                    				5)) {
                        dav_add_attr_ns(ctx->scratchpool, link, ctx->ns, "rel",
                                "alternate");
                    }
                    else {
                        dav_add_attr_ns(ctx->scratchpool, link, ctx->ns, "rel",
                                "enclosure");
                        dav_add_attr_ns(ctx->scratchpool, link, ctx->ns, "type",
                        		contenttype->first_cdata.first->text);
                        if (contentlength && contentlength->first_cdata.first->text) {
                            dav_add_attr_ns(ctx->scratchpool, link, ctx->ns, "length",
                            		contentlength->first_cdata.first->text);
                        }
                    }
                    dav_add_attr_ns(ctx->scratchpool, link, ctx->ns, "href",
                            entry_link);
                }

                if (!err) {
                    dav_send_atom_entry(ctx, ctx->r, entry, response->namespaces);

                    ctx->count++;
                }
            }

        }


        dav_close_propdb(propdb);
    }

    /* at this point, ctx->scratchpool has been used to stream a
       single response.  this function fully controls the pool, and
       thus has the right to clear it for the next iteration of this
       callback. */
    apr_pool_clear(ctx->scratchpool);

    return err;
}

static int dav_atom_handle_get(request_rec *r)
{
    dav_error *err;
    const dav_provider *provider;
    dav_resource *resource = NULL;
    dav_atom_ctx ctx = { { 0 } };
    dav_response *multi_status;
    const char *etag;
    int depth = 1;
    int status;

    /* for us? */
    if (!r->handler || strcmp(r->handler, DIR_MAGIC_TYPE)) {
        return DECLINED;
    }

    /* find the dav provider */
    provider = dav_get_provider(r);
    if (provider == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                 "DAV not enabled for %s, ignoring GET request",
                 ap_escape_html(r->pool, r->uri));
        return DECLINED;
    }

    /* resolve atom resource */
    if ((err = provider->repos->get_resource(r, NULL, NULL, 0, &resource))) {
        return dav_handle_err(r, err, NULL);
    }

    /* not existing or not a collection? not for us */
    if (!resource->exists || !resource->collection) {
        return DECLINED;
    }

    ctx.w.walk_type = DAV_WALKTYPE_NORMAL | DAV_WALKTYPE_AUTH;
    ctx.w.walk_ctx = &ctx;
    ctx.w.func = dav_atom_get_walker;
    ctx.w.pool = r->pool;
    ctx.w.root = resource;

    ctx.r = r;
    ctx.bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    apr_pool_create(&ctx.scratchpool, r->pool);
    apr_pool_tag(ctx.scratchpool, "mod_dav-scratch");


    /* ### should open read-only */
    if ((err = dav_open_lockdb(r, 0, &ctx.w.lockdb)) != NULL) {
        err = dav_push_error(r->pool, err->status, 0,
                             "The lock database could not be opened, "
                             "preventing access to the various lock "
                             "properties for the atom GET.",
                             err);
        return dav_handle_err(r, err, NULL);
    }
    if (ctx.w.lockdb != NULL) {
        /* if we have a lock database, then we can walk locknull resources */
        ctx.w.walk_type |= DAV_WALKTYPE_LOCKNULL;
    }

    /* Have the provider walk the resource. */
    etag = (*resource->hooks->getetag)(resource);

    if (etag) {
        apr_table_set(r->headers_out, "ETag", etag);
    }

    /* handle conditional requests */
    status = ap_meets_conditions(r);
    if (status) {
        return status;
    }

    /* Have the provider walk the resource. */
    err = (*resource->hooks->walk)(&ctx.w, depth, &multi_status);

    if (ctx.w.lockdb != NULL) {
        (*ctx.w.lockdb->hooks->close_lockdb)(ctx.w.lockdb);
    }

    if (err != NULL) {
        /* If an error occurred during the resource walk, there's
           basically nothing we can do but abort the connection and
           log an error.  This is one of the limitations of HTTP; it
           needs to "know" the entire status of the response before
           generating it, which is just impossible in these streamy
           response situations. */
        err = dav_push_error(r->pool, err->status, 0,
                             "Provider encountered an error while streaming"
                             " a multistatus PROPFIND response.", err);
        dav_log_err(r, err, APLOG_ERR);
        r->connection->aborted = 1;
        return DONE;
    }

    /* send <atom:feed> tag if not already sent above */

    dav_begin_atom_feed(&ctx, r, HTTP_OK, NULL, NULL);

    dav_finish_atom_feed(&ctx, r);

    /* the response has been sent. */
    return DONE;
}

static int dav_atom_handler(request_rec *r)
{
    dav_atom_config_rec *conf = ap_get_module_config(r->per_dir_config,
            &dav_atom_module);

    if (!conf || !conf->dav_atom) {
        return DECLINED;
    }

    if (r->method_number == M_GET) {
        return dav_atom_handle_get(r);
    }

    return DECLINED;
}

static void register_hooks(apr_pool_t *p)
{
    static const char * const aszSucc[]={ "mod_dav_autoindex.c",
                                          "mod_autoindex.c",
                                          "mod_userdir.c",
                                          "mod_vhost_alias.c", NULL };

    ap_hook_type_checker(dav_atom_type_checker, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(dav_atom_handler, NULL, aszSucc, APR_HOOK_MIDDLE);

}

AP_DECLARE_MODULE(dav_atom) =
{
    STANDARD20_MODULE_STUFF,
    create_dav_atom_dir_config, /* dir config creater */
    merge_dav_atom_dir_config,  /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server config */
    dav_atom_cmds,              /* command apr_table_t */
    register_hooks              /* register hooks */
};
