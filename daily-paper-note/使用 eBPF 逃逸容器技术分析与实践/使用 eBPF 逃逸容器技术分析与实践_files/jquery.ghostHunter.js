/**
* ghostHunter - 0.3.5
 * Copyright (C) 2014 Jamal Neufeld (jamal@i11u.me)
 * MIT Licensed
 * @license
*/
(function( $ ) {

    //This is the main plugin definition
    $.fn.ghostHunter    = function( options ) {

        //Here we use jQuery's extend to set default values if they weren't set by the user
        var opts        = $.extend( {}, $.fn.ghostHunter.defaults, options );
        if( opts.results )
        {
            pluginMethods.init( this , opts );
            return pluginMethods;
        }
    };

    $.fn.ghostHunter.defaults = {
        resultsData         : false,
        onPageLoad          : false,
        onKeyUp             : false,
        result_template     : "<a href='{{link}}'><p><h2>{{title}}</h2></p></a>",
        info_template       : "<p>共找到: {{amount}} 篇文章</p>",
        displaySearchInfo   : true,
        zeroResultsInfo     : true,
        before              : false,
        onComplete          : false,
        includepages        : false,
        filterfields        : false
    };

    var pluginMethods   = {

        isInit          : false,

        init            : function( target , opts ){
            var that                = this;
            this.target             = target;
            this.results            = opts.results;
            this.blogData           = [];
            this.result_template    = opts.result_template;
            this.info_template      = opts.info_template;
            this.zeroResultsInfo    = opts.zeroResultsInfo;
            this.displaySearchInfo  = opts.displaySearchInfo;
            this.before             = opts.before;
            this.onComplete         = opts.onComplete;
            this.includepages       = opts.includepages;
            this.filterfields       = opts.filterfields;

            if ( opts.onPageLoad ) {
                that.loadAPI();
            } else {
                target.focus(function(){
                    that.loadAPI();
                });
            }

            target.closest("form").submit(function(e){
                e.preventDefault();
                if(target.val()){
                    that.find(target.val());
                }
            });

            if( opts.onKeyUp ) {
                target.keyup(function() {
                    that.find(target.val());
                });
            }

            target.closest("form").find('.search-button').click(function(){
                if(target.val()){
                    that.find(target.val());
                }
            });

        },

        loadAPI         : function(){

            if(this.isInit) return false;

        /*  Here we load all of the blog posts to the index.
            This function will not call on load to avoid unnecessary heavy
            operations on a page if a visitor never ends up searching anything. */

            var index       = this.index,
                blogData    = this.blogData;
                obj         = {limit: "all",  include: "tags", fields: 'tags, title, id ,slug ,url'};
                            if  ( this.includepages ){
                                obj.filter="(page:true,page:false)";
                            }

            var that = this;
            $.get(ghost.url.api('posts',obj)).done(function(data){
                searchData = data.posts;
                searchData.forEach(function(arrayItem){
                    var tag_arr = arrayItem.tags.map(function(v) {
                        return v.name; // `tag` object has an `name` property which is the value of tag. If you also want other info, check API and get that property
                    })
                    var category = tag_arr.join(", ");
                    if (category.length < 1){
                        category = "undefined";
                    }
                    var parsedData  = {
                        id          : String(arrayItem.id),
                        title       : String(arrayItem.title),
                        pubDate     : String(arrayItem.created_at),
                        tag         : category,
                        link        : String(arrayItem.url)
                    }

                    blogData.push(parsedData);
                });
				if(that.target.val()){
					that.find(that.target.val());
				}
            });
            this.isInit = true;

		
        },

        find            : function(value){

            var searchResult = [];
            for(var i=0; i < this.blogData.length; i++) {
                if(value && this.blogData[i].title.toLowerCase().search(value.toLowerCase()) != -1){
                    searchResult.push(this.blogData[i]);
                }
            }
            var results         = $(this.results);
            var resultsData     = [];
            results.empty();

            if(this.before) {
                this.before();
            };

            if(this.zeroResultsInfo || searchResult.length > 0)
            {
                if(this.displaySearchInfo) results.append(this.format(this.info_template,{"amount":searchResult.length}));
            }

            for (var i = 0; i < searchResult.length; i++)
            {
                var link     = searchResult[i].link;
                var title    = searchResult[i].title;
                var postData = {
                    'link': link,
                    'title': title
                }
                results.append(this.format(this.result_template, postData));
                resultsData.push(postData);
            }

            if(this.onComplete) {
                this.onComplete(resultsData);
            };
        },

        clear           : function(){
            $(this.results).empty();
            this.target.val("");
        },

        format          : function (t, d) {
            return t.replace(/{#([^{}]*)#}/g, function (a, b) {
                var r = d[b];
                return typeof r === 'string' || typeof r === 'number' ? r : a;
            });
        }
    }

})( jQuery );

